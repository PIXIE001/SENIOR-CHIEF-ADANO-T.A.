require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");

const app = express();

app.use(helmet({
  crossOriginResourcePolicy: false
}));

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api/", limiter);

const SUPABASE_URL = String(process.env.SUPABASE_URL || "")
  .replace(/\/+$/, "");

const SUPABASE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY || "";

const JWT_SECRET =
  process.env.JWT_SECRET || "";

const SCHOOL_LAT = 1.735369;
const SCHOOL_LON = 40.038490;
const DEFAULT_RADIUS = 500;


/* =========================================================
   BASIC CHECKS
========================================================= */

if (!SUPABASE_URL) {
  console.error("Missing SUPABASE_URL");
}

if (!SUPABASE_KEY) {
  console.error("Missing SUPABASE_SERVICE_ROLE_KEY");
}

if (!JWT_SECRET) {
  console.error("Missing JWT_SECRET");
}


/* =========================================================
   SUPABASE REST HELPER
========================================================= */

async function supabaseRequest(
  table,
  options = {}
) {
  const url =
    `${SUPABASE_URL}/rest/v1/${table}`;

  const headers = {
    apikey: SUPABASE_KEY,
    Authorization: `Bearer ${SUPABASE_KEY}`,
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  const response = await fetch(url, {
    ...options,
    headers
  });

  const text = await response.text();

  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!response.ok) {
    const error =
      typeof data === "string"
        ? data
        : data?.message ||
          data?.error ||
          `Supabase error ${response.status}`;

    const err = new Error(error);
    err.status = response.status;
    throw err;
  }

  return data;
}


/* =========================================================
   JWT
========================================================= */

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: String(user.role || "")
        .trim()
        .toLowerCase()
    },
    JWT_SECRET,
    {
      expiresIn: "12h"
    }
  );
}


function setAuthCookie(res, user) {
  const token = createToken(user);

  res.cookie("scagss_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 12 * 60 * 60 * 1000
  });

  return token;
}


function getToken(req) {
  if (req.cookies?.scagss_token) {
    return req.cookies.scagss_token;
  }

  const header =
    req.headers.authorization || "";

  if (header.startsWith("Bearer ")) {
    return header.substring(7);
  }

  return null;
}


function requireAuth(req, res, next) {
  try {
    const token = getToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication required."
      });
    }

    req.user = jwt.verify(
      token,
      JWT_SECRET
    );

    next();

  } catch {
    return res.status(401).json({
      success: false,
      message: "Your session has expired. Please log in again."
    });
  }
}


function requireAdmin(req, res, next) {
  const role =
    String(req.user?.role || "")
      .trim()
      .toLowerCase();

  if (role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Administrator access required."
    });
  }

  next();
}


/* =========================================================
   DISTANCE / GPS
========================================================= */

function distanceInMeters(
  lat1,
  lon1,
  lat2,
  lon2
) {
  const R = 6371000;

  const p1 =
    Number(lat1) * Math.PI / 180;

  const p2 =
    Number(lat2) * Math.PI / 180;

  const dp =
    (Number(lat2) - Number(lat1))
    * Math.PI / 180;

  const dl =
    (Number(lon2) - Number(lon1))
    * Math.PI / 180;

  const a =
    Math.sin(dp / 2) ** 2 +
    Math.cos(p1) *
    Math.cos(p2) *
    Math.sin(dl / 2) ** 2;

  const c =
    2 * Math.atan2(
      Math.sqrt(a),
      Math.sqrt(1 - a)
    );

  return R * c;
}


function validCoordinate(value) {
  return Number.isFinite(Number(value));
}


async function getSchoolSettings() {
  try {
    const rows =
      await supabaseRequest(
        "school_settings",
        {
          method: "GET",
          headers: {
            Prefer: "return=representation"
          }
        }
      );

    if (
      Array.isArray(rows) &&
      rows.length > 0
    ) {
      return {
        latitude: Number(rows[0].latitude),
        longitude: Number(rows[0].longitude),
        radius:
          Number(rows[0].radius) ||
          DEFAULT_RADIUS
      };
    }
  } catch (error) {
    console.error(
      "School settings error:",
      error.message
    );
  }

  return {
    latitude: SCHOOL_LAT,
    longitude: SCHOOL_LON,
    radius: DEFAULT_RADIUS
  };
}


/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "online",
    portal: "S.C.A.G.S.S Staff Portal",
    version: "2.0",
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
      const login = String(
        req.body.login ||
        req.body.username ||
        req.body.email ||
        ""
      ).trim();

      const password =
        String(req.body.password || "");

      if (!login || !password) {
        return res.status(400).json({
          success: false,
          message:
            "Username/email and password are required."
        });
      }

      let users =
        await supabaseRequest(
          "staff",
          {
            method: "GET",
            headers: {
              Prefer: "return=representation"
            }
          }
        );

      users = Array.isArray(users)
        ? users
        : [];

      const loginLower =
        login.toLowerCase();

      const user =
        users.find(u =>
          String(u.username || "")
            .toLowerCase() === loginLower
        ) ||
        users.find(u =>
          String(u.email || "")
            .toLowerCase() === loginLower
        ) ||
        users.find(u =>
          String(u.full_name || "")
            .toLowerCase() === loginLower
        );

      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Invalid login details."
        });
      }

      const passwordOK =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!passwordOK) {
        return res.status(401).json({
          success: false,
          message: "Invalid login details."
        });
      }

      const role =
        String(user.role || "")
          .trim()
          .toLowerCase();

      if (
        role !== "admin" &&
        user.active !== true
      ) {
        return res.status(403).json({
          success: false,
          pending: true,
          message:
            "Your registration is pending administrator approval."
        });
      }

      const safeUser = {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        email: user.email || "",
        phone: user.phone || "",
        role,
        active: user.active
      };

      setAuthCookie(res, safeUser);

      return res.json({
        success: true,
        message: "Login successful.",
        user: safeUser
      });

    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Server error while processing login."
      });
    }
  }
);


/* =========================================================
   TEACHER REGISTRATION
========================================================= */

app.post(
  "/api/auth/register",
  async (req, res) => {
    try {
      const fullName =
        String(req.body.full_name || "")
          .trim();

      const email =
        String(req.body.email || "")
          .trim()
          .toLowerCase();

      const phone =
        String(req.body.phone || "")
          .trim();

      const password =
        String(req.body.password || "");

      if (
        !fullName ||
        !email ||
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

      const existing =
        await supabaseRequest(
          "staff",
          {
            method: "GET"
          }
        );

      const users =
        Array.isArray(existing)
          ? existing
          : [];

      const emailExists =
        users.some(u =>
          String(u.email || "")
            .toLowerCase() === email
        );

      if (emailExists) {
        return res.status(409).json({
          success: false,
          message:
            "An account with this email already exists."
        });
      }

      const baseUsername =
        fullName
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, ".")
          .replace(/^\.+|\.+$/g, "");

      let username =
        baseUsername ||
        `teacher${Date.now()}`;

      let counter = 2;

      while (
        users.some(u =>
          String(u.username || "")
            .toLowerCase() ===
          username.toLowerCase()
        )
      ) {
        username =
          `${baseUsername}.${counter}`;
        counter++;
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const created =
        await supabaseRequest(
          "staff",
          {
            method: "POST",
            headers: {
              Prefer:
                "return=representation"
            },
            body: JSON.stringify({
              username,
              password_hash:
                passwordHash,
              full_name:
                fullName,
              email,
              phone,
              role: "teacher",
              active: false
            })
          }
        );

      return res.status(201).json({
        success: true,
        pending: true,
        message:
          "Registration successful. Your account is pending administrator approval.",
        username,
        staff: Array.isArray(created)
          ? created[0]
          : created
      });

    } catch (error) {
      console.error(
        "REGISTRATION ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Server error while processing registration."
      });
    }
  }
);


/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/me",
  requireAuth,
  async (req, res) => {
    try {
      const rows =
        await supabaseRequest(
          "staff",
          {
            method: "GET"
          }
        );

      const user =
        (Array.isArray(rows)
          ? rows
          : []
        ).find(
          u => Number(u.id) ===
            Number(req.user.id)
        );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User account not found."
        });
      }

      res.json({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          full_name: user.full_name,
          email: user.email || "",
          phone: user.phone || "",
          role: String(user.role || "")
            .trim()
            .toLowerCase(),
          active: user.active
        }
      });

    } catch (error) {
      console.error(
        "ME ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Unable to load your account."
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
    res.clearCookie(
      "scagss_token",
      {
        httpOnly: true,
        sameSite: "lax",
        secure:
          process.env.NODE_ENV ===
          "production"
      }
    );

    res.json({
      success: true,
      message: "Logged out successfully."
    });
  }
);


/* =========================================================
   ADMIN: ALL STAFF
========================================================= */

app.get(
  "/api/admin/staff",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const rows =
        await supabaseRequest(
          "staff",
          {
            method: "GET"
          }
        );

      const staff =
        (Array.isArray(rows)
          ? rows
          : []
        ).map(u => ({
          id: u.id,
          username: u.username,
          full_name: u.full_name,
          email: u.email || "",
          phone: u.phone || "",
          role: String(u.role || "")
            .trim()
            .toLowerCase(),
          active: u.active,
          created_at: u.created_at
        }));

      res.json({
        success: true,
        staff
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Unable to load staff."
      });
    }
  }
);


/* =========================================================
   ADMIN: APPROVE / DEACTIVATE
========================================================= */

app.patch(
  "/api/admin/staff/:id/status",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const active =
        Boolean(req.body.active);

      if (!Number.isFinite(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid staff ID."
        });
      }

      const updated =
        await supabaseRequest(
          `staff?id=eq.${id}`,
          {
            method: "PATCH",
            headers: {
              Prefer:
                "return=representation"
            },
            body: JSON.stringify({
              active
            })
          }
        );

      res.json({
        success: true,
        message:
          active
            ? "Staff member approved/activated."
            : "Staff member deactivated.",
        staff:
          Array.isArray(updated)
            ? updated[0]
            : updated
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Unable to update staff status."
      });
    }
  }
);


/* =========================================================
   ADMIN: DELETE STAFF
========================================================= */

app.delete(
  "/api/admin/staff/:id",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      if (!Number.isFinite(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid staff ID."
        });
      }

      if (
        Number(req.user.id) === id
      ) {
        return res.status(400).json({
          success: false,
          message:
            "You cannot delete your own administrator account."
        });
      }

      await supabaseRequest(
        `staff?id=eq.${id}`,
        {
          method: "DELETE"
        }
      );

      res.json({
        success: true,
        message:
          "Staff member deleted."
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Unable to delete staff member."
      });
    }
  }
);


/* =========================================================
   TEACHER: PROFILE
========================================================= */

app.get(
  "/api/staff/profile",
  requireAuth,
  async (req, res) => {
    try {
      const rows =
        await supabaseRequest(
          `staff?id=eq.${Number(req.user.id)}`,
          {
            method: "GET"
          }
        );

      if (
        !Array.isArray(rows) ||
        rows.length === 0
      ) {
        return res.status(404).json({
          success: false,
          message:
            "Profile not found."
        });
      }

      const user = rows[0];

      res.json({
        success: true,
        profile: {
          id: user.id,
          username: user.username,
          full_name: user.full_name,
          email: user.email || "",
          phone: user.phone || "",
          role: String(user.role || "")
            .trim()
            .toLowerCase(),
          active: user.active,
          created_at: user.created_at
        }
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Unable to load profile."
      });
    }
  }
);


/* =========================================================
   GPS CLOCK IN
========================================================= */

app.post(
  "/api/attendance/clock-in",
  requireAuth,
  async (req, res) => {
    try {
      const lat =
        Number(req.body.latitude);

      const lon =
        Number(req.body.longitude);

      const accuracy =
        Number(req.body.accuracy);

      if (
        !validCoordinate(lat) ||
        !validCoordinate(lon)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Valid GPS coordinates are required."
        });
      }

      const school =
        await getSchoolSettings();

      const distance =
        distanceInMeters(
          lat,
          lon,
          school.latitude,
          school.longitude
        );

      const verified =
        distance <= school.radius;

      if (!verified) {
        return res.status(403).json({
          success: false,
          gps_verified: false,
          distance: Math.round(distance),
          radius: school.radius,
          message:
            `Clock-in denied. You are approximately ${Math.round(distance)} metres from the school. You must be within ${school.radius} metres.`
        });
      }

      const today =
        new Date()
          .toISOString()
          .slice(0, 10);

      const existing =
        await supabaseRequest(
          `attendance?staff_id=eq.${Number(req.user.id)}&attendance_date=eq.${today}`,
          {
            method: "GET"
          }
        );

      if (
        Array.isArray(existing) &&
        existing.length > 0 &&
        existing[0].clock_in
      ) {
        return res.status(409).json({
          success: false,
          message:
            "You have already clocked in today.",
          attendance: existing[0]
        });
      }

      const record = {
        staff_id: Number(req.user.id),
        attendance_date: today,
        clock_in: new Date().toISOString(),
        status: "present",
        gps_verified: true,
        clock_in_lat: lat,
        clock_in_lon: lon,
        clock_in_accuracy:
          Number.isFinite(accuracy)
            ? accuracy
            : null,
        clock_in_distance:
          distance
      };

      let result;

      if (
        Array.isArray(existing) &&
        existing.length > 0
      ) {
        result =
          await supabaseRequest(
            `attendance?id=eq.${existing[0].id}`,
            {
              method: "PATCH",
              headers: {
                Prefer:
                  "return=representation"
              },
              body:
                JSON.stringify(record)
            }
          );
      } else {
        result =
          await supabaseRequest(
            "attendance",
            {
              method: "POST",
              headers: {
                Prefer:
                  "return=representation"
              },
              body:
                JSON.stringify(record)
            }
          );
      }

      res.json({
        success: true,
        message:
          "Clock-in successful. GPS verified.",
        gps_verified: true,
        distance: Math.round(distance),
        radius: school.radius,
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
          "Unable to process clock-in."
      });
    }
  }
);


/* =========================================================
   GPS CLOCK OUT
========================================================= */

app.post(
  "/api/attendance/clock-out",
  requireAuth,
  async (req, res) => {
    try {
      const lat =
        Number(req.body.latitude);

      const lon =
        Number(req.body.longitude);

      const accuracy =
        Number(req.body.accuracy);

      if (
        !validCoordinate(lat) ||
        !validCoordinate(lon)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Valid GPS coordinates are required."
        });
      }

      const school =
        await getSchoolSettings();

      const distance =
        distanceInMeters(
          lat,
          lon,
          school.latitude,
          school.longitude
        );

      const verified =
        distance <= school.radius;

      if (!verified) {
        return res.status(403).json({
          success: false,
          gps_verified: false,
          distance: Math.round(distance),
          radius: school.radius,
          message:
            `Clock-out denied. You are approximately ${Math.round(distance)} metres from the school.`
        });
      }

      const today =
        new Date()
          .toISOString()
          .slice(0, 10);

      const existing =
        await supabaseRequest(
          `attendance?staff_id=eq.${Number(req.user.id)}&attendance_date=eq.${today}`,
          {
            method: "GET"
          }
        );

      if (
        !Array.isArray(existing) ||
        existing.length === 0 ||
        !existing[0].clock_in
      ) {
        return res.status(400).json({
          success: false,
          message:
            "You must clock in before clocking out."
        });
      }

      if (existing[0].clock_out) {
        return res.status(409).json({
          success: false,
          message:
            "You have already clocked out today."
        });
      }

      const result =
        await supabaseRequest(
          `attendance?id=eq.${existing[0].id}`,
          {
            method: "PATCH",
            headers: {
              Prefer:
                "return=representation"
            },
            body: JSON.stringify({
              clock_out:
                new Date().toISOString(),
              clock_out_lat:
                lat,
              clock_out_lon:
                lon,
              clock_out_accuracy:
                Number.isFinite(accuracy)
                  ? accuracy
                  : null,
              clock_out_distance:
                distance,
              gps_verified: true
            })
          }
        );

      res.json({
        success: true,
        message:
          "Clock-out successful. GPS verified.",
        gps_verified: true,
        distance: Math.round(distance),
        radius: school.radius,
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
          "Unable to process clock-out."
      });
    }
  }
);


/* =========================================================
   TEACHER ATTENDANCE
========================================================= */

app.get(
  "/api/attendance/my",
  requireAuth,
  async (req, res) => {
    try {
      const rows =
        await supabaseRequest(
          `attendance?staff_id=eq.${Number(req.user.id)}&order=attendance_date.desc`,
          {
            method: "GET"
          }
        );

      res.json({
        success: true,
        attendance:
          Array.isArray(rows)
            ? rows
            : []
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Unable to load attendance."
      });
    }
  }
);


/* =========================================================
   ADMIN: ALL ATTENDANCE
========================================================= */

app.get(
  "/api/admin/attendance",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const attendance =
        await supabaseRequest(
          "attendance?order=attendance_date.desc,clock_in.desc",
          {
            method: "GET"
          }
        );

      const staff =
        await supabaseRequest(
          "staff",
          {
            method: "GET"
          }
        );

      const staffMap =
        new Map(
          (Array.isArray(staff)
            ? staff
            : []
          ).map(s => [
            Number(s.id),
            s
          ])
        );

      const result =
        (Array.isArray(attendance)
          ? attendance
          : []
        ).map(a => {
          const s =
            staffMap.get(
              Number(a.staff_id)
            );

          return {
            ...a,
            staff_name:
              s?.full_name || "Unknown",
            username:
              s?.username || ""
          };
        });

      res.json({
        success: true,
        attendance: result
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Unable to load attendance."
      });
    }
  }
);


/* =========================================================
   ADMIN: GPS MONITOR
========================================================= */

app.get(
  "/api/admin/gps",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const attendance =
        await supabaseRequest(
          "attendance?order=attendance_date.desc,clock_in.desc",
          {
            method: "GET"
          }
        );

      const staff =
        await supabaseRequest(
          "staff",
          {
            method: "GET"
          }
        );

      const staffMap =
        new Map(
          (Array.isArray(staff)
            ? staff
            : []
          ).map(s => [
            Number(s.id),
            s
          ])
        );

      const gps =
        (Array.isArray(attendance)
          ? attendance
          : []
        )
          .filter(a =>
            a.clock_in_lat !== null ||
            a.clock_out_lat !== null
          )
          .map(a => {
            const s =
              staffMap.get(
                Number(a.staff_id)
              );

            return {
              attendance_id: a.id,
              staff_id: a.staff_id,
              staff_name:
                s?.full_name ||
                "Unknown",
              username:
                s?.username || "",
              date:
                a.attendance_date,

              clock_in:
                a.clock_in,
              clock_out:
                a.clock_out,

              clock_in_lat:
                a.clock_in_lat,
              clock_in_lon:
                a.clock_in_lon,
              clock_in_accuracy:
                a.clock_in_accuracy,
              clock_in_distance:
                a.clock_in_distance,

              clock_out_lat:
                a.clock_out_lat,
              clock_out_lon:
                a.clock_out_lon,
              clock_out_accuracy:
                a.clock_out_accuracy,
              clock_out_distance:
                a.clock_out_distance,

              gps_verified:
                a.gps_verified
            };
          });

      const school =
        await getSchoolSettings();

      res.json({
        success: true,
        school,
        gps
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Unable to load GPS records."
      });
    }
  }
);


/* =========================================================
   SCHOOL GPS SETTINGS
========================================================= */

app.get(
  "/api/admin/settings/gps",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const school =
        await getSchoolSettings();

      res.json({
        success: true,
        settings: school
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Unable to load GPS settings."
      });
    }
  }
);


app.patch(
  "/api/admin/settings/gps",
  requireAuth,
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
            "Valid latitude, longitude and radius are required."
        });
      }

      const existing =
        await supabaseRequest(
          "school_settings",
          {
            method: "GET"
          }
        );

      let result;

      if (
        Array.isArray(existing) &&
        existing.length > 0
      ) {
        result =
          await supabaseRequest(
            `school_settings?id=eq.${existing[0].id}`,
            {
              method: "PATCH",
              headers: {
                Prefer:
                  "return=representation"
              },
              body: JSON.stringify({
                latitude,
                longitude,
                radius,
                updated_at:
                  new Date().toISOString()
              })
            }
          );
      } else {
        result =
          await supabaseRequest(
            "school_settings",
            {
              method: "POST",
              headers: {
                Prefer:
                  "return=representation"
              },
              body: JSON.stringify({
                latitude,
                longitude,
                radius
              })
            }
          );
      }

      res.json({
        success: true,
        message:
          "School GPS settings updated.",
        settings:
          Array.isArray(result)
            ? result[0]
            : result
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Unable to update GPS settings."
      });
    }
  }
);


/* =========================================================
   REPORTS
========================================================= */

app.get(
  "/api/admin/reports/teacher/:id",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const staffId =
        Number(req.params.id);

      const from =
        String(req.query.from || "");

      const to =
        String(req.query.to || "");

      if (!Number.isFinite(staffId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid teacher ID."
        });
      }

      let query =
        `attendance?staff_id=eq.${staffId}&order=attendance_date.desc`;

      if (from) {
        query +=
          `&attendance_date=gte.${encodeURIComponent(from)}`;
      }

      if (to) {
        query +=
          `&attendance_date=lte.${encodeURIComponent(to)}`;
      }

      const attendance =
        await supabaseRequest(
          query,
          {
            method: "GET"
          }
        );

      const staff =
        await supabaseRequest(
          `staff?id=eq.${staffId}`,
          {
            method: "GET"
          }
        );

      const teacher =
        Array.isArray(staff)
          ? staff[0]
          : null;

      if (!teacher) {
        return res.status(404).json({
          success: false,
          message:
            "Teacher not found."
        });
      }

      const records =
        Array.isArray(attendance)
          ? attendance
          : [];

      const present =
        records.filter(
          r => r.status === "present"
        ).length;

      const gpsVerified =
        records.filter(
          r => r.gps_verified === true
        ).length;

      res.json({
        success: true,
        teacher: {
          id: teacher.id,
          full_name:
            teacher.full_name,
          username:
            teacher.username,
          email:
            teacher.email || "",
          phone:
            teacher.phone || ""
        },
        summary: {
          total_days:
            records.length,
          present,
          gps_verified:
            gpsVerified
        },
        attendance: records
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Unable to generate report."
      });
    }
  }
);


/* =========================================================
   ADMIN: DASHBOARD SUMMARY
========================================================= */

app.get(
  "/api/admin/summary",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const staff =
        await supabaseRequest(
          "staff",
          {
            method: "GET"
          }
        );

      const attendance =
        await supabaseRequest(
          "attendance",
          {
            method: "GET"
          }
        );

      const users =
        Array.isArray(staff)
          ? staff
          : [];

      const records =
        Array.isArray(attendance)
          ? attendance
          : [];

      const teachers =
        users.filter(
          u =>
            String(u.role || "")
              .toLowerCase() ===
            "teacher"
        );

      const pending =
        teachers.filter(
          u => u.active !== true
        );

      const today =
        new Date()
          .toISOString()
          .slice(0, 10);

      const todayRecords =
        records.filter(
          r =>
            r.attendance_date ===
            today
        );

      const clockedIn =
        todayRecords.filter(
          r =>
            r.clock_in &&
            !r.clock_out
        );

      const gpsVerified =
        todayRecords.filter(
          r =>
            r.gps_verified === true
        );

      res.json({
        success: true,
        summary: {
          total_staff:
            teachers.length,
          pending:
            pending.length,
          clocked_in:
            clockedIn.length,
          gps_verified:
            gpsVerified.length,
          today:
            todayRecords.length
        }
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Unable to load dashboard summary."
      });
    }
  }
);


/* =========================================================
   LESSON ATTENDANCE
========================================================= */

app.get(
  "/api/admin/lessons",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const tableExists =
        await supabaseRequest(
          "lesson_attendance",
          {
            method: "GET"
          }
        );

      res.json({
        success: true,
        lessons:
          Array.isArray(tableExists)
            ? tableExists
            : []
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        message:
          "Lesson attendance table has not been created yet."
      });
    }
  }
);


app.post(
  "/api/admin/lessons",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const record = {
        teacher_name:
          String(
            req.body.teacher_name || ""
          ).trim(),

        class_name:
          String(
            req.body.class_name || ""
          ).trim(),

        subject:
          String(
            req.body.subject || ""
          ).trim(),

        attendance_date:
          String(
            req.body.attendance_date ||
            new Date()
              .toISOString()
              .slice(0, 10)
          ),

        present:
          Number(req.body.present || 0),

        absent:
          Number(req.body.absent || 0),

        notes:
          String(
            req.body.notes || ""
          ).trim()
      };

      if (
        !record.teacher_name ||
        !record.class_name ||
        !record.subject
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Teacher, class and subject are required."
        });
      }

      const result =
        await supabaseRequest(
          "lesson_attendance",
          {
            method: "POST",
            headers: {
              Prefer:
                "return=representation"
            },
            body:
              JSON.stringify(record)
          }
        );

      res.status(201).json({
        success: true,
        message:
          "Lesson attendance saved.",
        lesson:
          Array.isArray(result)
            ? result[0]
            : result
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Unable to save lesson attendance. Make sure the lesson_attendance table exists."
      });
    }
  }
);


/* =========================================================
   AI ASSISTANT — LOCAL ANALYSIS
========================================================= */

app.post(
  "/api/admin/ai/analyze",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const question =
        String(
          req.body.question || ""
        ).trim();

      const attendance =
        await supabaseRequest(
          "attendance",
          {
            method: "GET"
          }
        );

      const staff =
        await supabaseRequest(
          "staff",
          {
            method: "GET"
          }
        );

      const records =
        Array.isArray(attendance)
          ? attendance
          : [];

      const users =
        Array.isArray(staff)
          ? staff
          : [];

      const teachers =
        users.filter(
          u =>
            String(u.role || "")
              .toLowerCase() ===
            "teacher"
        );

      const totalRecords =
        records.length;

      const gpsVerified =
        records.filter(
          r =>
            r.gps_verified === true
        ).length;

      const clockedOut =
        records.filter(
          r =>
            r.clock_out
        ).length;

      const clockedIn =
        records.filter(
          r =>
            r.clock_in &&
            !r.clock_out
        ).length;

      const response = {
        question,

        overview:
          `There are currently ${teachers.length} registered teachers and ${totalRecords} attendance records.`,

        attendance:
          `${clockedIn} attendance record(s) show staff currently clocked in, while ${clockedOut} record(s) contain a clock-out time.`,

        gps:
          `${gpsVerified} attendance record(s) have GPS verification.`,

        recommendation:
          gpsVerified < totalRecords
            ? "Review attendance records without GPS verification."
            : "GPS verification is recorded for all available attendance records."
      };

      res.json({
        success: true,
        analysis: response
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "AI analysis could not be completed."
      });
    }
  }
);


/* =========================================================
   404 API
========================================================= */

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      success: false,
      message:
        "API endpoint not found."
    });
  }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      "UNHANDLED ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message:
        "Internal server error."
    });
  }
);


/* =========================================================
   LOCAL SERVER
========================================================= */

const PORT =
  process.env.PORT || 3000;

if (require.main === module) {
  app.listen(
    PORT,
    () => {
      console.log(
        `S.C.A.G.S.S Staff Portal API running on port ${PORT}`
      );
    }
  );
}


module.exports = app;
