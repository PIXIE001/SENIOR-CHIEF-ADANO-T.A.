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
   CONFIGURATION
========================================================= */

const PORT = process.env.PORT || 3000;

const SUPABASE_URL = (process.env.SUPABASE_URL || "")
  .replace(/\/$/, "")
  .replace(/\/rest\/v1$/, "");

const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const JWT_SECRET = process.env.JWT_SECRET || "";

const COOKIE_NAME = "scagss_token";

const SCHOOL_DEFAULT_LAT = 1.735369;
const SCHOOL_DEFAULT_LON = 40.038490;
const SCHOOL_DEFAULT_RADIUS = 500;

/* =========================================================
   BASIC SAFETY CHECK
========================================================= */

if (!SUPABASE_URL || !SUPABASE_KEY || !JWT_SECRET) {
  console.error("Missing required environment variables.");
}

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

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api/", limiter);

/* =========================================================
   SUPABASE REST HELPER
========================================================= */

async function supabaseRequest(path, options = {}) {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error("Supabase environment variables are missing.");
  }

  const url = `${SUPABASE_URL}/rest/v1/${path}`;

  const headers = {
    apikey: SUPABASE_KEY,
    Authorization: `Bearer ${SUPABASE_KEY}`,
    "Content-Type": "application/json",
    Prefer: options.prefer || "return=representation",
    ...(options.headers || {})
  };

  const response = await fetch(url, {
    method: options.method || "GET",
    headers,
    body:
      options.body !== undefined
        ? JSON.stringify(options.body)
        : undefined
  });

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
        ? data.message || data.details || data.hint || JSON.stringify(data)
        : String(data);

    const error = new Error(message);
    error.status = response.status;
    error.supabase = data;

    throw error;
  }

  return data;
}

/* =========================================================
   JWT HELPERS
========================================================= */

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

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/"
  });
}

function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/"
  });
}

function getToken(req) {
  return req.cookies ? req.cookies[COOKIE_NAME] : null;
}

function authenticate(req, res, next) {
  try {
    const token = getToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Not authenticated."
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Session expired. Please log in again."
    });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Administrator access required."
    });
  }

  next();
}

/* =========================================================
   GENERAL HELPERS
========================================================= */

function clean(value) {
  if (value === undefined || value === null) {
    return "";
  }

  return String(value).trim();
}

function normalizeEmail(value) {
  return clean(value).toLowerCase();
}

function normalizeUsername(value) {
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

function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371000;

  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) ** 2;

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c;
}

function validCoordinate(value) {
  return Number.isFinite(Number(value));
}

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/api/health", async (req, res) => {
  let databaseConfigured = false;

  try {
    databaseConfigured =
      Boolean(SUPABASE_URL) &&
      Boolean(SUPABASE_KEY) &&
      Boolean(JWT_SECRET);

    return res.json({
      success: true,
      service: "S.C.A.G.S.S Staff Portal",
      databaseConfigured,
      time: new Date().toISOString()
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const login = clean(req.body.login || req.body.username);
    const password = clean(req.body.password);

    if (!login || !password) {
      return res.status(400).json({
        success: false,
        message: "Enter your name/email and password."
      });
    }

    let staff = null;

    /* Try username */
    const usernameRows = await supabaseRequest(
      `staff?select=*&username=eq.${encodeURIComponent(
        normalizeUsername(login)
      )}&limit=1`
    );

    if (Array.isArray(usernameRows) && usernameRows.length) {
      staff = usernameRows[0];
    }

    /* Try email */
    if (!staff && login.includes("@")) {
      const emailRows = await supabaseRequest(
        `staff?select=*&email=ilike.${encodeURIComponent(
          login
        )}&limit=1`
      );

      if (Array.isArray(emailRows) && emailRows.length) {
        staff = emailRows[0];
      }
    }

    /* Try exact teacher name */
    if (!staff) {
      const nameRows = await supabaseRequest(
        `staff?select=*&full_name=ilike.${encodeURIComponent(
          login
        )}&limit=2`
      );

      if (Array.isArray(nameRows) && nameRows.length === 1) {
        staff = nameRows[0];
      }

      if (Array.isArray(nameRows) && nameRows.length > 1) {
        return res.status(409).json({
          success: false,
          message:
            "More than one staff member has this name. Please log in using your email."
        });
      }
    }

    if (!staff) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details."
      });
    }

    if (!staff.active) {
      return res.status(403).json({
        success: false,
        message: "Your account has not been approved or has been deactivated."
      });
    }

    const passwordCorrect = await bcrypt.compare(
      password,
      staff.password_hash
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details."
      });
    }

    const token = createToken(staff);

    setAuthCookie(res, token);

    return res.json({
      success: true,
      message: "Login successful.",
      user: safeStaff(staff)
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Server error while logging in.",
      error:
        process.env.NODE_ENV === "production"
          ? undefined
          : error.message
    });
  }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/auth/logout", (req, res) => {
  clearAuthCookie(res);

  return res.json({
    success: true,
    message: "Logged out successfully."
  });
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get("/api/me", authenticate, async (req, res) => {
  try {
    const rows = await supabaseRequest(
      `staff?select=id,username,full_name,email,phone,role,active,created_at&id=eq.${req.user.id}&limit=1`
    );

    if (!rows.length) {
      clearAuthCookie(res);

      return res.status(404).json({
        success: false,
        message: "User account not found."
      });
    }

    return res.json({
      success: true,
      user: safeStaff(rows[0])
    });
  } catch (error) {
    console.error("ME ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load user profile."
    });
  }
});

/* =========================================================
   GPS SETTINGS
========================================================= */

app.get("/api/settings/gps", authenticate, async (req, res) => {
  try {
    const rows = await supabaseRequest(
      "school_settings?select=*&order=id.asc&limit=1"
    );

    if (!rows.length) {
      return res.json({
        success: true,
        settings: {
          latitude: SCHOOL_DEFAULT_LAT,
          longitude: SCHOOL_DEFAULT_LON,
          radius: SCHOOL_DEFAULT_RADIUS
        }
      });
    }

    return res.json({
      success: true,
      settings: rows[0]
    });
  } catch (error) {
    console.error("GPS GET ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load GPS settings."
    });
  }
});

app.put(
  "/api/settings/gps",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const latitude = Number(req.body.latitude);
      const longitude = Number(req.body.longitude);
      const radius = Number(req.body.radius);

      if (
        !validCoordinate(latitude) ||
        !validCoordinate(longitude) ||
        !Number.isFinite(radius) ||
        radius <= 0
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid GPS settings."
        });
      }

      const existing = await supabaseRequest(
        "school_settings?select=id&order=id.asc&limit=1"
      );

      let result;

      if (existing.length) {
        result = await supabaseRequest(
          `school_settings?id=eq.${existing[0].id}`,
          {
            method: "PATCH",
            body: {
              latitude,
              longitude,
              radius,
              updated_at: new Date().toISOString()
            }
          }
        );
      } else {
        result = await supabaseRequest("school_settings", {
          method: "POST",
          body: {
            latitude,
            longitude,
            radius
          }
        });
      }

      return res.json({
        success: true,
        settings: Array.isArray(result) ? result[0] : result
      });
    } catch (error) {
      console.error("GPS UPDATE ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to update GPS settings.",
        error:
          process.env.NODE_ENV === "production"
            ? undefined
            : error.message
      });
    }
  }
);

/* =========================================================
   GET SCHOOL GPS
========================================================= */

async function getSchoolSettings() {
  const rows = await supabaseRequest(
    "school_settings?select=*&order=id.asc&limit=1"
  );

  if (!rows.length) {
    return {
      latitude: SCHOOL_DEFAULT_LAT,
      longitude: SCHOOL_DEFAULT_LON,
      radius: SCHOOL_DEFAULT_RADIUS
    };
  }

  return rows[0];
}

/* =========================================================
   TEACHER CLOCK-IN
========================================================= */

app.post("/api/attendance/clock-in", authenticate, async (req, res) => {
  try {
    if (req.user.role !== "teacher") {
      return res.status(403).json({
        success: false,
        message: "Only teachers can clock in."
      });
    }

    const lat = Number(req.body.latitude);
    const lon = Number(req.body.longitude);
    const accuracy = Number(req.body.accuracy || 0);

    if (!validCoordinate(lat) || !validCoordinate(lon)) {
      return res.status(400).json({
        success: false,
        message: "GPS location is required."
      });
    }

    const settings = await getSchoolSettings();

    const distance = haversineDistance(
      lat,
      lon,
      Number(settings.latitude),
      Number(settings.longitude)
    );

    if (distance > Number(settings.radius)) {
      return res.status(403).json({
        success: false,
        message: `You are outside the school attendance area. Distance: ${Math.round(
          distance
        )} metres.`,
        distance: Math.round(distance),
        allowed_radius: Number(settings.radius)
      });
    }

    const today = new Date().toISOString().slice(0, 10);

    const existing = await supabaseRequest(
      `attendance?select=*&staff_id=eq.${req.user.id}&attendance_date=eq.${today}&limit=1`
    );

    if (existing.length && existing[0].clock_in) {
      return res.status(409).json({
        success: false,
        message: "You have already clocked in today.",
        attendance: existing[0]
      });
    }

    const payload = {
      staff_id: req.user.id,
      attendance_date: today,
      clock_in: new Date().toISOString(),
      status: "Present",
      gps_verified: true,
      clock_in_lat: lat,
      clock_in_lon: lon,
      clock_in_accuracy: Number.isFinite(accuracy) ? accuracy : null,
      clock_in_distance: distance
    };

    let result;

    if (existing.length) {
      result = await supabaseRequest(
        `attendance?id=eq.${existing[0].id}`,
        {
          method: "PATCH",
          body: payload
        }
      );
    } else {
      result = await supabaseRequest("attendance", {
        method: "POST",
        body: payload
      });
    }

    return res.json({
      success: true,
      message: "Clock-in successful.",
      attendance: Array.isArray(result) ? result[0] : result
    });
  } catch (error) {
    console.error("CLOCK IN ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Server error while clocking in.",
      error:
        process.env.NODE_ENV === "production"
          ? undefined
          : error.message
    });
  }
});

/* =========================================================
   TEACHER CLOCK-OUT
========================================================= */

app.post("/api/attendance/clock-out", authenticate, async (req, res) => {
  try {
    if (req.user.role !== "teacher") {
      return res.status(403).json({
        success: false,
        message: "Only teachers can clock out."
      });
    }

    const lat = Number(req.body.latitude);
    const lon = Number(req.body.longitude);
    const accuracy = Number(req.body.accuracy || 0);

    if (!validCoordinate(lat) || !validCoordinate(lon)) {
      return res.status(400).json({
        success: false,
        message: "GPS location is required."
      });
    }

    const settings = await getSchoolSettings();

    const distance = haversineDistance(
      lat,
      lon,
      Number(settings.latitude),
      Number(settings.longitude)
    );

    if (distance > Number(settings.radius)) {
      return res.status(403).json({
        success: false,
        message: `You are outside the school attendance area. Distance: ${Math.round(
          distance
        )} metres.`,
        distance: Math.round(distance),
        allowed_radius: Number(settings.radius)
      });
    }

    const today = new Date().toISOString().slice(0, 10);

    const existing = await supabaseRequest(
      `attendance?select=*&staff_id=eq.${req.user.id}&attendance_date=eq.${today}&limit=1`
    );

    if (!existing.length || !existing[0].clock_in) {
      return res.status(400).json({
        success: false,
        message: "You must clock in before clocking out."
      });
    }

    if (existing[0].clock_out) {
      return res.status(409).json({
        success: false,
        message: "You have already clocked out today."
      });
    }

    const result = await supabaseRequest(
      `attendance?id=eq.${existing[0].id}`,
      {
        method: "PATCH",
        body: {
          clock_out: new Date().toISOString(),
          clock_out_lat: lat,
          clock_out_lon: lon,
          clock_out_accuracy: Number.isFinite(accuracy)
            ? accuracy
            : null,
          clock_out_distance: distance
        }
      }
    );

    return res.json({
      success: true,
      message: "Clock-out successful.",
      attendance: Array.isArray(result) ? result[0] : result
    });
  } catch (error) {
    console.error("CLOCK OUT ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Server error while clocking out."
    });
  }
});

/* =========================================================
   TEACHER TODAY ATTENDANCE
========================================================= */

app.get("/api/attendance/today", authenticate, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);

    const rows = await supabaseRequest(
      `attendance?select=*&staff_id=eq.${req.user.id}&attendance_date=eq.${today}&limit=1`
    );

    return res.json({
      success: true,
      attendance: rows[0] || null
    });
  } catch (error) {
    console.error("TODAY ATTENDANCE ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load today's attendance."
    });
  }
});

/* =========================================================
   TEACHER HISTORY
========================================================= */

app.get("/api/attendance/history", authenticate, async (req, res) => {
  try {
    const limit = Math.min(
      Math.max(Number(req.query.limit) || 100, 1),
      500
    );

    const rows = await supabaseRequest(
      `attendance?select=*&staff_id=eq.${req.user.id}&order=attendance_date.desc&limit=${limit}`
    );

    return res.json({
      success: true,
      attendance: rows
    });
  } catch (error) {
    console.error("HISTORY ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to load attendance history."
    });
  }
});

/* =========================================================
   ADMIN - STAFF LIST
========================================================= */

app.get(
  "/api/admin/staff",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const rows = await supabaseRequest(
        "staff?select=id,username,full_name,email,phone,role,active,created_at&order=full_name.asc"
      );

      return res.json({
        success: true,
        staff: rows
      });
    } catch (error) {
      console.error("STAFF LIST ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to load staff."
      });
    }
  }
);

/* =========================================================
   ADMIN - REGISTER TEACHER
========================================================= */

app.post(
  "/api/admin/staff",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const fullName = clean(req.body.full_name);
      const email = normalizeEmail(req.body.email);
      const phone = clean(req.body.phone);
      const password = clean(req.body.password);

      if (!fullName || !email || !phone || !password) {
        return res.status(400).json({
          success: false,
          message:
            "Full name, email, phone number and password are required."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: "Password must contain at least 6 characters."
        });
      }

      /* Check duplicate email */
      const duplicateEmail = await supabaseRequest(
        `staff?select=id&email=ilike.${encodeURIComponent(
          email
        )}&limit=1`
      );

      if (duplicateEmail.length) {
        return res.status(409).json({
          success: false,
          message: "This email is already registered."
        });
      }

      /*
       * Internal username.
       * The teacher logs in using their FULL NAME or EMAIL,
       * so the internal username does not need to be exposed.
       */
      let baseUsername = fullName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, ".")
        .replace(/^\.+|\.+$/g, "");

      if (!baseUsername) {
        baseUsername = "teacher";
      }

      let username = baseUsername;
      let counter = 2;

      while (true) {
        const existing = await supabaseRequest(
          `staff?select=id&username=eq.${encodeURIComponent(
            username
          )}&limit=1`
        );

        if (!existing.length) break;

        username = `${baseUsername}.${counter}`;
        counter++;
      }

      const passwordHash = await bcrypt.hash(password, 12);

      const result = await supabaseRequest("staff", {
        method: "POST",
        body: {
          username,
          password_hash: passwordHash,
          full_name: fullName,
          email,
          phone,
          role: "teacher",
          active: true
        }
      });

      const created = Array.isArray(result) ? result[0] : result;

      return res.status(201).json({
        success: true,
        message: "Teacher registered successfully.",
        staff: safeStaff(created)
      });
    } catch (error) {
      console.error("REGISTER TEACHER ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Server error while registering teacher.",
        error:
          process.env.NODE_ENV === "production"
            ? undefined
            : error.message
      });
    }
  }
);

/* =========================================================
   ADMIN - ACTIVATE / DEACTIVATE STAFF
========================================================= */

app.patch(
  "/api/admin/staff/:id/status",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid staff ID."
        });
      }

      const active =
        req.body.active === true ||
        req.body.active === "true";

      const result = await supabaseRequest(
        `staff?id=eq.${id}`,
        {
          method: "PATCH",
          body: {
            active
          }
        }
      );

      return res.json({
        success: true,
        message: active
          ? "Staff account activated."
          : "Staff account deactivated.",
        staff: Array.isArray(result) ? result[0] : result
      });
    } catch (error) {
      console.error("STATUS ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to update staff status."
      });
    }
  }
);

/* =========================================================
   ADMIN - STAFF PROFILE UPDATE
========================================================= */

app.patch(
  "/api/admin/staff/:id",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid staff ID."
        });
      }

      const fullName = clean(req.body.full_name);
      const email = normalizeEmail(req.body.email);
      const phone = clean(req.body.phone);

      if (!fullName || !email || !phone) {
        return res.status(400).json({
          success: false,
          message: "Name, email and phone are required."
        });
      }

      const duplicate = await supabaseRequest(
        `staff?select=id&email=ilike.${encodeURIComponent(
          email
        )}&id=neq.${id}&limit=1`
      );

      if (duplicate.length) {
        return res.status(409).json({
          success: false,
          message: "Another staff member is using this email."
        });
      }

      const result = await supabaseRequest(
        `staff?id=eq.${id}`,
        {
          method: "PATCH",
          body: {
            full_name: fullName,
            email,
            phone
          }
        }
      );

      return res.json({
        success: true,
        message: "Staff profile updated.",
        staff: Array.isArray(result) ? result[0] : result
      });
    } catch (error) {
      console.error("PROFILE UPDATE ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to update staff profile."
      });
    }
  }
);

/* =========================================================
   ADMIN - RESET PASSWORD
========================================================= */

app.patch(
  "/api/admin/staff/:id/password",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);
      const password = clean(req.body.password);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid staff ID."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: "Password must contain at least 6 characters."
        });
      }

      const passwordHash = await bcrypt.hash(password, 12);

      await supabaseRequest(
        `staff?id=eq.${id}`,
        {
          method: "PATCH",
          body: {
            password_hash: passwordHash
          }
        }
      );

      return res.json({
        success: true,
        message: "Password updated successfully."
      });
    } catch (error) {
      console.error("PASSWORD RESET ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to reset password."
      });
    }
  }
);

/* =========================================================
   ADMIN - TODAY ATTENDANCE
========================================================= */

app.get(
  "/api/admin/attendance/today",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const today = new Date().toISOString().slice(0, 10);

      const rows = await supabaseRequest(
        `attendance?select=*,staff(id,full_name,email,phone,role)&attendance_date=eq.${today}&order=clock_in.asc`
      );

      return res.json({
        success: true,
        date: today,
        attendance: rows
      });
    } catch (error) {
      console.error("ADMIN ATTENDANCE ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to load today's attendance."
      });
    }
  }
);

/* =========================================================
   ADMIN - GPS MONITOR
========================================================= */

app.get(
  "/api/admin/gps/today",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const today = new Date().toISOString().slice(0, 10);

      const rows = await supabaseRequest(
        `attendance?select=*,staff(id,full_name,email,phone)&attendance_date=eq.${today}&order=clock_in.asc`
      );

      const gps = rows.map((row) => ({
        attendance_id: row.id,
        staff_id: row.staff_id,
        staff_name: row.staff?.full_name || "Unknown",
        email: row.staff?.email || "",
        phone: row.staff?.phone || "",
        clock_in: row.clock_in,
        clock_out: row.clock_out,
        gps_verified: row.gps_verified,
        clock_in_lat: row.clock_in_lat,
        clock_in_lon: row.clock_in_lon,
        clock_in_accuracy: row.clock_in_accuracy,
        clock_in_distance: row.clock_in_distance,
        clock_out_lat: row.clock_out_lat,
        clock_out_lon: row.clock_out_lon,
        clock_out_accuracy: row.clock_out_accuracy,
        clock_out_distance: row.clock_out_distance
      }));

      return res.json({
        success: true,
        date: today,
        gps
      });
    } catch (error) {
      console.error("GPS MONITOR ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to load GPS attendance."
      });
    }
  }
);

/* =========================================================
   ADMIN - SUMMARY
========================================================= */

app.get(
  "/api/admin/summary",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const today = new Date().toISOString().slice(0, 10);

      const staffRows = await supabaseRequest(
        "staff?select=id,role,active"
      );

      const attendanceRows = await supabaseRequest(
        `attendance?select=id,staff_id,clock_in,clock_out,status&attendance_date=eq.${today}`
      );

      const teachers = staffRows.filter(
        (s) => s.role === "teacher"
      );

      const activeTeachers = teachers.filter(
        (s) => s.active
      );

      const present = attendanceRows.filter(
        (a) => a.clock_in
      );

      const clockedOut = attendanceRows.filter(
        (a) => a.clock_out
      );

      return res.json({
        success: true,
        date: today,
        total_staff: staffRows.length,
        total_teachers: teachers.length,
        active_teachers: activeTeachers.length,
        present_today: present.length,
        clocked_out_today: clockedOut.length,
        absent_today: Math.max(
          activeTeachers.length - present.length,
          0
        )
      });
    } catch (error) {
      console.error("SUMMARY ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to load dashboard summary."
      });
    }
  }
);

/* =========================================================
   ADMIN - ATTENDANCE DETAIL
========================================================= */

app.get(
  "/api/admin/attendance/:id",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid attendance ID."
        });
      }

      const rows = await supabaseRequest(
        `attendance?select=*,staff(id,full_name,email,phone,role)&id=eq.${id}&limit=1`
      );

      if (!rows.length) {
        return res.status(404).json({
          success: false,
          message: "Attendance record not found."
        });
      }

      return res.json({
        success: true,
        attendance: rows[0]
      });
    } catch (error) {
      console.error("ATTENDANCE DETAIL ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to load attendance detail."
      });
    }
  }
);

/* =========================================================
   ADMIN - INDIVIDUAL REPORT
========================================================= */

app.get(
  "/api/admin/report",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const staffId = Number(req.query.staff_id);
      const from = clean(req.query.from);
      const to = clean(req.query.to);

      if (!Number.isInteger(staffId)) {
        return res.status(400).json({
          success: false,
          message: "A valid staff ID is required."
        });
      }

      if (!from || !to) {
        return res.status(400).json({
          success: false,
          message: "Start and end dates are required."
        });
      }

      const staffRows = await supabaseRequest(
        `staff?select=id,username,full_name,email,phone,role,active&id=eq.${staffId}&limit=1`
      );

      if (!staffRows.length) {
        return res.status(404).json({
          success: false,
          message: "Staff member not found."
        });
      }

      const attendanceRows = await supabaseRequest(
        `attendance?select=*&staff_id=eq.${staffId}&attendance_date=gte.${encodeURIComponent(
          from
        )}&attendance_date=lte.${encodeURIComponent(
          to
        )}&order=attendance_date.asc`
      );

      const daysPresent = attendanceRows.filter(
        (row) => row.clock_in
      ).length;

      const daysClockedOut = attendanceRows.filter(
        (row) => row.clock_out
      ).length;

      const gpsVerified = attendanceRows.filter(
        (row) => row.gps_verified
      ).length;

      return res.json({
        success: true,
        staff: safeStaff(staffRows[0]),
        period: {
          from,
          to
        },
        summary: {
          attendance_records: attendanceRows.length,
          days_present: daysPresent,
          days_clocked_out: daysClockedOut,
          gps_verified: gpsVerified
        },
        attendance: attendanceRows
      });
    } catch (error) {
      console.error("REPORT ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to generate report.",
        error:
          process.env.NODE_ENV === "production"
            ? undefined
            : error.message
      });
    }
  }
);

/* =========================================================
   AI ASSISTANT PLACEHOLDER
========================================================= */

app.post(
  "/api/ai/assistant",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const message = clean(req.body.message);

      if (!message) {
        return res.status(400).json({
          success: false,
          message: "Enter a question."
        });
      }

      return res.json({
        success: true,
        reply:
          "The S.C.A.G.S.S AI Assistant is ready for integration. The secure AI connection will be added after the portal backend is confirmed working."
      });
    } catch (error) {
      console.error("AI ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "AI assistant error."
      });
    }
  }
);

/* =========================================================
   404 API HANDLER
========================================================= */

app.use("/api", (req, res) => {
  return res.status(404).json({
    success: false,
    message: "API endpoint not found.",
    path: req.originalUrl
  });
});

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error("GLOBAL ERROR:", error);

  if (res.headersSent) {
    return next(error);
  }

  return res.status(500).json({
    success: false,
    message: "A server error occurred.",
    error:
      process.env.NODE_ENV === "production"
        ? undefined
        : error.message
  });
});

/* =========================================================
   VERCEL EXPORT
========================================================= */

module.exports = app;
