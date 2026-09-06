require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const SUPABASE_URL = (process.env.SUPABASE_URL || "")
  .replace(/\/$/, "")
  .replace(/\/rest\/v1$/, "");

const SUPABASE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY || "";

const JWT_SECRET =
  process.env.JWT_SECRET || "";

const COOKIE_NAME = "scagss_token";

const DEFAULT_LAT = 1.735369;
const DEFAULT_LON = 40.038490;
const DEFAULT_RADIUS = 500;

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  cors({
    origin: true,
    credentials: true
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
  "/api/",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false
  })
);

/* =========================================================
   SUPABASE
========================================================= */

async function supabaseRequest(path, options = {}) {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error(
      "Supabase environment variables are not configured."
    );
  }

  const response = await fetch(
    `${SUPABASE_URL}/rest/v1/${path}`,
    {
      method: options.method || "GET",
      headers: {
        apikey: SUPABASE_KEY,
        Authorization: `Bearer ${SUPABASE_KEY}`,
        "Content-Type": "application/json",
        Prefer:
          options.prefer || "return=representation",
        ...(options.headers || {})
      },
      body:
        options.body !== undefined
          ? JSON.stringify(options.body)
          : undefined
    }
  );

  const text = await response.text();

  let data;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!response.ok) {
    const message =
      typeof data === "object" && data !== null
        ? data.message ||
          data.details ||
          data.hint ||
          JSON.stringify(data)
        : String(data);

    const error = new Error(message);
    error.status = response.status;
    error.supabase = data;

    throw error;
  }

  return data;
}

/* =========================================================
   HELPERS
========================================================= */

function clean(value) {
  if (value === undefined || value === null) {
    return "";
  }

  return String(value).trim();
}

function email(value) {
  return clean(value).toLowerCase();
}

function safeStaff(staff) {
  if (!staff) return null;

  return {
    id: staff.id,
    username: staff.username,
    full_name: staff.full_name,
    email: staff.email || "",
    phone: staff.phone || "",
    role: staff.role,
    active: staff.active,
    created_at: staff.created_at
  };
}

function createToken(staff) {
  return jwt.sign(
    {
      id: staff.id,
      username: staff.username,
      full_name: staff.full_name,
      role: staff.role
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function authenticate(req, res, next) {
  try {
    const token =
      req.cookies && req.cookies[COOKIE_NAME];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Not authenticated."
      });
    }

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    req.user = decoded;

    next();
  } catch {
    return res.status(401).json({
      success: false,
      message:
        "Your session has expired. Please log in again."
    });
  }
}

function requireAdmin(req, res, next) {
  if (
    !req.user ||
    req.user.role !== "admin"
  ) {
    return res.status(403).json({
      success: false,
      message:
        "Administrator access required."
    });
  }

  next();
}

function setCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge:
      7 * 24 * 60 * 60 * 1000,
    path: "/"
  });
}

function clearCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/"
  });
}

function haversine(
  lat1,
  lon1,
  lat2,
  lon2
) {
  const R = 6371000;

  const dLat =
    ((lat2 - lat1) * Math.PI) / 180;

  const dLon =
    ((lon2 - lon1) * Math.PI) / 180;

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(
      (lat1 * Math.PI) / 180
    ) *
      Math.cos(
        (lat2 * Math.PI) / 180
      ) *
      Math.sin(dLon / 2) ** 2;

  return (
    R *
    2 *
    Math.atan2(
      Math.sqrt(a),
      Math.sqrt(1 - a)
    )
  );
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service:
      "S.C.A.G.S.S Staff Portal",
    databaseConfigured:
      Boolean(
        SUPABASE_URL &&
          SUPABASE_KEY &&
          JWT_SECRET
      ),
    time: new Date().toISOString()
  });
});

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      const login = clean(
        req.body.login ||
          req.body.username ||
          req.body.email
      );

      const password = clean(
        req.body.password
      );

      if (!login || !password) {
        return res.status(400).json({
          success: false,
          message:
            "Enter your username, name or email and password."
        });
      }

      let staff = null;

      /*
       * 1. USERNAME
       *
       * ilike allows:
       * Admin.001
       * admin.001
       * ADMIN.001
       */

      const usernameRows =
        await supabaseRequest(
          `staff?select=*&username=ilike.${encodeURIComponent(
            login
          )}&limit=1`
        );

      if (
        Array.isArray(usernameRows) &&
        usernameRows.length > 0
      ) {
        staff = usernameRows[0];
      }

      /*
       * 2. EMAIL
       */

      if (!staff) {
        const emailRows =
          await supabaseRequest(
            `staff?select=*&email=ilike.${encodeURIComponent(
              login
            )}&limit=1`
          );

        if (
          Array.isArray(emailRows) &&
          emailRows.length > 0
        ) {
          staff = emailRows[0];
        }
      }

      /*
       * 3. FULL NAME
       */

      if (!staff) {
        const nameRows =
          await supabaseRequest(
            `staff?select=*&full_name=ilike.${encodeURIComponent(
              login
            )}&limit=2`
          );

        if (
          Array.isArray(nameRows) &&
          nameRows.length === 1
        ) {
          staff = nameRows[0];
        }

        if (
          Array.isArray(nameRows) &&
          nameRows.length > 1
        ) {
          return res.status(409).json({
            success: false,
            message:
              "More than one staff member has this name. Please use your email."
          });
        }
      }

      if (!staff) {
        return res.status(401).json({
          success: false,
          message:
            "Invalid login details."
        });
      }

      if (!staff.active) {
        return res.status(403).json({
          success: false,
          message:
            "Your account is not active. Please contact the administrator."
        });
      }

      if (!staff.password_hash) {
        return res.status(500).json({
          success: false,
          message:
            "This account has no password configured."
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          staff.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          success: false,
          message:
            "Invalid login details."
        });
      }

      const token =
        createToken(staff);

      setCookie(res, token);

      return res.json({
        success: true,
        message:
          "Login successful.",
        user: safeStaff(staff)
      });
    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Server error while logging in."
      });
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/auth/logout",
  (req, res) => {
    clearCookie(res);

    res.json({
      success: true,
      message:
        "Logged out successfully."
    });
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/me",
  authenticate,
  async (req, res) => {
    try {
      const rows =
        await supabaseRequest(
          `staff?select=id,username,full_name,email,phone,role,active,created_at&id=eq.${req.user.id}&limit=1`
        );

      if (!rows.length) {
        clearCookie(res);

        return res.status(404).json({
          success: false,
          message:
            "User account not found."
        });
      }

      res.json({
        success: true,
        user: safeStaff(rows[0])
      });
    } catch (error) {
      console.error(
        "ME ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load your profile."
      });
    }
  }
);

/* =========================================================
   GPS SETTINGS
========================================================= */

async function getGPS() {
  const rows =
    await supabaseRequest(
      "school_settings?select=*&order=id.asc&limit=1"
    );

  if (!rows.length) {
    return {
      latitude: DEFAULT_LAT,
      longitude: DEFAULT_LON,
      radius: DEFAULT_RADIUS
    };
  }

  return rows[0];
}

app.get(
  "/api/settings/gps",
  authenticate,
  async (req, res) => {
    try {
      res.json({
        success: true,
        settings: await getGPS()
      });
    } catch (error) {
      console.error(
        "GPS GET ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load GPS settings."
      });
    }
  }
);

app.put(
  "/api/settings/gps",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const latitude =
        Number(req.body.latitude);

      const longitude =
        Number(req.body.longitude);

      const radius =
        Number(req.body.radius);

      if (
        !Number.isFinite(latitude) ||
        !Number.isFinite(longitude) ||
        !Number.isFinite(radius) ||
        radius <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid GPS settings."
        });
      }

      const existing =
        await supabaseRequest(
          "school_settings?select=id&order=id.asc&limit=1"
        );

      let result;

      if (existing.length) {
        result =
          await supabaseRequest(
            `school_settings?id=eq.${existing[0].id}`,
            {
              method: "PATCH",
              body: {
                latitude,
                longitude,
                radius,
                updated_at:
                  new Date().toISOString()
              }
            }
          );
      } else {
        result =
          await supabaseRequest(
            "school_settings",
            {
              method: "POST",
              body: {
                latitude,
                longitude,
                radius
              }
            }
          );
      }

      res.json({
        success: true,
        settings:
          Array.isArray(result)
            ? result[0]
            : result
      });
    } catch (error) {
      console.error(
        "GPS UPDATE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to update GPS settings."
      });
    }
  }
);

/* =========================================================
   TEACHER CLOCK IN
========================================================= */

app.post(
  "/api/attendance/clock-in",
  authenticate,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        "teacher"
      ) {
        return res.status(403).json({
          success: false,
          message:
            "Only teachers can clock in."
        });
      }

      const lat =
        Number(req.body.latitude);

      const lon =
        Number(req.body.longitude);

      const accuracy =
        Number(
          req.body.accuracy || 0
        );

      if (
        !Number.isFinite(lat) ||
        !Number.isFinite(lon)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "GPS location is required."
        });
      }

      const gps =
        await getGPS();

      const distance =
        haversine(
          lat,
          lon,
          Number(gps.latitude),
          Number(gps.longitude)
        );

      if (
        distance >
        Number(gps.radius)
      ) {
        return res.status(403).json({
          success: false,
          message:
            `You are outside the school attendance area. Distance: ${Math.round(
              distance
            )} metres.`,
          distance:
            Math.round(distance),
          allowed_radius:
            Number(gps.radius)
        });
      }

      const today =
        new Date()
          .toISOString()
          .slice(0, 10);

      const existing =
        await supabaseRequest(
          `attendance?select=*&staff_id=eq.${req.user.id}&attendance_date=eq.${today}&limit=1`
        );

      if (
        existing.length &&
        existing[0].clock_in
      ) {
        return res.status(409).json({
          success: false,
          message:
            "You have already clocked in today.",
          attendance:
            existing[0]
        });
      }

      const data = {
        staff_id:
          req.user.id,
        attendance_date:
          today,
        clock_in:
          new Date().toISOString(),
        status: "Present",
        gps_verified: true,
        clock_in_lat: lat,
        clock_in_lon: lon,
        clock_in_accuracy:
          accuracy,
        clock_in_distance:
          distance
      };

      let result;

      if (existing.length) {
        result =
          await supabaseRequest(
            `attendance?id=eq.${existing[0].id}`,
            {
              method: "PATCH",
              body: data
            }
          );
      } else {
        result =
          await supabaseRequest(
            "attendance",
            {
              method: "POST",
              body: data
            }
          );
      }

      res.json({
        success: true,
        message:
          "Clock-in successful.",
        attendance:
          Array.isArray(result)
            ? result[0]
            : result
      });
    } catch (error) {
      console.error(
        "CLOCK IN ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Server error while clocking in."
      });
    }
  }
);

/* =========================================================
   TEACHER CLOCK OUT
========================================================= */

app.post(
  "/api/attendance/clock-out",
  authenticate,
  async (req, res) => {
    try {
      if (
        req.user.role !==
        "teacher"
      ) {
        return res.status(403).json({
          success: false,
          message:
            "Only teachers can clock out."
        });
      }

      const lat =
        Number(req.body.latitude);

      const lon =
        Number(req.body.longitude);

      const accuracy =
        Number(
          req.body.accuracy || 0
        );

      if (
        !Number.isFinite(lat) ||
        !Number.isFinite(lon)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "GPS location is required."
        });
      }

      const gps =
        await getGPS();

      const distance =
        haversine(
          lat,
          lon,
          Number(gps.latitude),
          Number(gps.longitude)
        );

      if (
        distance >
        Number(gps.radius)
      ) {
        return res.status(403).json({
          success: false,
          message:
            `You are outside the school attendance area. Distance: ${Math.round(
              distance
            )} metres.`,
          distance:
            Math.round(distance)
        });
      }

      const today =
        new Date()
          .toISOString()
          .slice(0, 10);

      const rows =
        await supabaseRequest(
          `attendance?select=*&staff_id=eq.${req.user.id}&attendance_date=eq.${today}&limit=1`
        );

      if (
        !rows.length ||
        !rows[0].clock_in
      ) {
        return res.status(400).json({
          success: false,
          message:
            "You must clock in first."
        });
      }

      if (rows[0].clock_out) {
        return res.status(409).json({
          success: false,
          message:
            "You have already clocked out today."
        });
      }

      const result =
        await supabaseRequest(
          `attendance?id=eq.${rows[0].id}`,
          {
            method: "PATCH",
            body: {
              clock_out:
                new Date().toISOString(),
              clock_out_lat:
                lat,
              clock_out_lon:
                lon,
              clock_out_accuracy:
                accuracy,
              clock_out_distance:
                distance
            }
          }
        );

      res.json({
        success: true,
        message:
          "Clock-out successful.",
        attendance:
          Array.isArray(result)
            ? result[0]
            : result
      });
    } catch (error) {
      console.error(
        "CLOCK OUT ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Server error while clocking out."
      });
    }
  }
);

/* =========================================================
   TEACHER TODAY
========================================================= */

app.get(
  "/api/attendance/today",
  authenticate,
  async (req, res) => {
    try {
      const today =
        new Date()
          .toISOString()
          .slice(0, 10);

      const rows =
        await supabaseRequest(
          `attendance?select=*&staff_id=eq.${req.user.id}&attendance_date=eq.${today}&limit=1`
        );

      res.json({
        success: true,
        attendance:
          rows[0] || null
      });
    } catch (error) {
      console.error(
        "TODAY ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load today's attendance."
      });
    }
  }
);

/* =========================================================
   TEACHER HISTORY
========================================================= */

app.get(
  "/api/attendance/history",
  authenticate,
  async (req, res) => {
    try {
      const rows =
        await supabaseRequest(
          `attendance?select=*&staff_id=eq.${req.user.id}&order=attendance_date.desc&limit=500`
        );

      res.json({
        success: true,
        attendance: rows
      });
    } catch (error) {
      console.error(
        "HISTORY ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load attendance history."
      });
    }
  }
);

/* =========================================================
   ADMIN STAFF
========================================================= */

app.get(
  "/api/admin/staff",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const rows =
        await supabaseRequest(
          "staff?select=id,username,full_name,email,phone,role,active,created_at&order=full_name.asc"
        );

      res.json({
        success: true,
        staff: rows
      });
    } catch (error) {
      console.error(
        "STAFF ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load staff."
      });
    }
  }
);

/* =========================================================
   ADMIN REGISTER TEACHER
========================================================= */

app.post(
  "/api/admin/staff",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const fullName =
        clean(req.body.full_name);

      const staffEmail =
        email(req.body.email);

      const phone =
        clean(req.body.phone);

      const password =
        clean(req.body.password);

      if (
        !fullName ||
        !staffEmail ||
        !phone ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Full name, email, phone and password are required."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Password must contain at least 6 characters."
        });
      }

      const duplicateEmail =
        await supabaseRequest(
          `staff?select=id&email=ilike.${encodeURIComponent(
            staffEmail
          )}&limit=1`
        );

      if (duplicateEmail.length) {
        return res.status(409).json({
          success: false,
          message:
            "This email is already registered."
        });
      }

      /*
       * INTERNAL USERNAME
       *
       * The teacher can log in using:
       * - this username
       * - their full name
       * - their email
       */

      let username =
        fullName
          .toLowerCase()
          .replace(
            /[^a-z0-9]+/g,
            "."
          )
          .replace(
            /^\.+|\.+$/g,
            ""
          );

      if (!username) {
        username =
          "teacher";
      }

      const original =
        username;

      let number = 2;

      while (true) {
        const exists =
          await supabaseRequest(
            `staff?select=id&username=ilike.${encodeURIComponent(
              username
            )}&limit=1`
          );

        if (!exists.length) {
          break;
        }

        username =
          `${original}.${number}`;

        number++;
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        await supabaseRequest(
          "staff",
          {
            method: "POST",
            body: {
              username,
              password_hash:
                passwordHash,
              full_name:
                fullName,
              email:
                staffEmail,
              phone,
              role:
                "teacher",
              active:
                true
            }
          }
        );

      const created =
        Array.isArray(result)
          ? result[0]
          : result;

      res.status(201).json({
        success: true,
        message:
          "Teacher registered successfully.",
        staff:
          safeStaff(created)
      });
    } catch (error) {
      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Server error while registering teacher."
      });
    }
  }
);

/* =========================================================
   ADMIN STAFF STATUS
========================================================= */

app.patch(
  "/api/admin/staff/:id/status",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const active =
        req.body.active === true ||
        req.body.active === "true";

      const result =
        await supabaseRequest(
          `staff?id=eq.${id}`,
          {
            method: "PATCH",
            body: {
              active
            }
          }
        );

      res.json({
        success: true,
        message:
          active
            ? "Staff account activated."
            : "Staff account deactivated.",
        staff:
          Array.isArray(result)
            ? result[0]
            : result
      });
    } catch (error) {
      console.error(
        "STATUS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to update staff status."
      });
    }
  }
);

/* =========================================================
   ADMIN PROFILE UPDATE
========================================================= */

app.patch(
  "/api/admin/staff/:id",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const fullName =
        clean(req.body.full_name);

      const staffEmail =
        email(req.body.email);

      const phone =
        clean(req.body.phone);

      if (
        !fullName ||
        !staffEmail ||
        !phone
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Name, email and phone are required."
        });
      }

      const duplicate =
        await supabaseRequest(
          `staff?select=id&email=ilike.${encodeURIComponent(
            staffEmail
          )}&id=neq.${id}&limit=1`
        );

      if (duplicate.length) {
        return res.status(409).json({
          success: false,
          message:
            "Another staff member uses this email."
        });
      }

      const result =
        await supabaseRequest(
          `staff?id=eq.${id}`,
          {
            method: "PATCH",
            body: {
              full_name:
                fullName,
              email:
                staffEmail,
              phone
            }
          }
        );

      res.json({
        success: true,
        message:
          "Profile updated.",
        staff:
          Array.isArray(result)
            ? result[0]
            : result
      });
    } catch (error) {
      console.error(
        "PROFILE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to update profile."
      });
    }
  }
);

/* =========================================================
   ADMIN RESET PASSWORD
========================================================= */

app.patch(
  "/api/admin/staff/:id/password",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const password =
        clean(req.body.password);

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Password must contain at least 6 characters."
        });
      }

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      await supabaseRequest(
        `staff?id=eq.${id}`,
        {
          method: "PATCH",
          body: {
            password_hash:
              hash
          }
        }
      );

      res.json({
        success: true,
        message:
          "Password updated successfully."
      });
    } catch (error) {
      console.error(
        "PASSWORD ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to reset password."
      });
    }
  }
);

/* =========================================================
   ADMIN TODAY ATTENDANCE
========================================================= */

app.get(
  "/api/admin/attendance/today",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const today =
        new Date()
          .toISOString()
          .slice(0, 10);

      const rows =
        await supabaseRequest(
          `attendance?select=*,staff(id,full_name,email,phone,role)&attendance_date=eq.${today}&order=clock_in.asc`
        );

      res.json({
        success: true,
        date: today,
        attendance: rows
      });
    } catch (error) {
      console.error(
        "ADMIN ATTENDANCE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load today's attendance."
      });
    }
  }
);

/* =========================================================
   ADMIN GPS
========================================================= */

app.get(
  "/api/admin/gps/today",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const today =
        new Date()
          .toISOString()
          .slice(0, 10);

      const rows =
        await supabaseRequest(
          `attendance?select=*,staff(id,full_name,email,phone)&attendance_date=eq.${today}&order=clock_in.asc`
        );

      res.json({
        success: true,
        date: today,
        gps: rows
      });
    } catch (error) {
      console.error(
        "GPS MONITOR ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load GPS records."
      });
    }
  }
);

/* =========================================================
   ADMIN SUMMARY
========================================================= */

app.get(
  "/api/admin/summary",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const today =
        new Date()
          .toISOString()
          .slice(0, 10);

      const staff =
        await supabaseRequest(
          "staff?select=id,role,active"
        );

      const attendance =
        await supabaseRequest(
          `attendance?select=id,staff_id,clock_in,clock_out,status&attendance_date=eq.${today}`
        );

      const teachers =
        staff.filter(
          s =>
            s.role ===
            "teacher"
        );

      const active =
        teachers.filter(
          s => s.active
        );

      const present =
        attendance.filter(
          a => a.clock_in
        );

      const clockedOut =
        attendance.filter(
          a => a.clock_out
        );

      res.json({
        success: true,
        date: today,
        total_staff:
          staff.length,
        total_teachers:
          teachers.length,
        active_teachers:
          active.length,
        present_today:
          present.length,
        clocked_out_today:
          clockedOut.length,
        absent_today:
          Math.max(
            active.length -
              present.length,
            0
          )
      });
    } catch (error) {
      console.error(
        "SUMMARY ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load dashboard summary."
      });
    }
  }
);

/* =========================================================
   ADMIN INDIVIDUAL REPORT
========================================================= */

app.get(
  "/api/admin/report",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const staffId =
        Number(
          req.query.staff_id
        );

      const from =
        clean(req.query.from);

      const to =
        clean(req.query.to);

      if (
        !Number.isInteger(
          staffId
        ) ||
        !from ||
        !to
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Staff member and date range are required."
        });
      }

      const staffRows =
        await supabaseRequest(
          `staff?select=id,username,full_name,email,phone,role,active,created_at&id=eq.${staffId}&limit=1`
        );

      if (!staffRows.length) {
        return res.status(404).json({
          success: false,
          message:
            "Staff member not found."
        });
      }

      const attendance =
        await supabaseRequest(
          `attendance?select=*&staff_id=eq.${staffId}&attendance_date=gte.${encodeURIComponent(
            from
          )}&attendance_date=lte.${encodeURIComponent(
            to
          )}&order=attendance_date.asc`
        );

      res.json({
        success: true,
        staff:
          safeStaff(
            staffRows[0]
          ),
        period: {
          from,
          to
        },
        summary: {
          records:
            attendance.length,
          days_present:
            attendance.filter(
              a => a.clock_in
            ).length,
          days_clocked_out:
            attendance.filter(
              a => a.clock_out
            ).length,
          gps_verified:
            attendance.filter(
              a =>
                a.gps_verified
            ).length
        },
        attendance
      });
    } catch (error) {
      console.error(
        "REPORT ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to generate report."
      });
    }
  }
);

/* =========================================================
   AI ASSISTANT
========================================================= */

app.post(
  "/api/ai/assistant",
  authenticate,
  requireAdmin,
  async (req, res) => {
    const message =
      clean(req.body.message);

    if (!message) {
      return res.status(400).json({
        success: false,
        message:
          "Enter a question."
      });
    }

    res.json({
      success: true,
      reply:
        "S.C.A.G.S.S AI Assistant is connected to the portal interface. The secure AI provider connection will be added after the attendance system is fully verified."
    });
  }
);

/* =========================================================
   API 404
========================================================= */

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      success: false,
      message:
        "API endpoint not found.",
      path:
        req.originalUrl
    });
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      "SERVER ERROR:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      success: false,
      message:
        "A server error occurred."
    });
  }
);

/* =========================================================
   VERCEL
========================================================= */

module.exports = app;
