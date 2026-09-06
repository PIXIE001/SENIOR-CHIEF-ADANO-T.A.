require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");

const app = express();

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

app.use(
  cors({
    origin: process.env.FRONTEND_URL || true,
    credentials: true
  })
);

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

function configurationReady() {
  return Boolean(
    SUPABASE_URL &&
      SUPABASE_SERVICE_ROLE_KEY &&
      JWT_SECRET
  );
}

/* =========================================================
   SUPABASE
========================================================= */

async function supabaseRequest(path, options = {}) {
  if (!configurationReady()) {
    throw new Error("Server configuration is incomplete.");
  }

  const response = await fetch(
    `${SUPABASE_URL}/rest/v1/${path}`,
    {
      ...options,
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        "Content-Type": "application/json",
        ...(options.headers || {})
      }
    }
  );

  const text = await response.text();

  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!response.ok) {
    const message =
      data?.message ||
      data?.hint ||
      data?.details ||
      "Supabase request failed.";

    throw new Error(message);
  }

  return data;
}

/* =========================================================
   JWT
========================================================= */

function createToken(staff) {
  return jwt.sign(
    {
      id: staff.id,
      username: staff.username,
      role: staff.role,
      full_name: staff.full_name
    },
    JWT_SECRET,
    {
      expiresIn: "12h"
    }
  );
}

function authenticate(req, res, next) {
  try {
    const token = req.cookies.scagss_token;

    if (!token) {
      return res.status(401).json({
        error: "Not authenticated."
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch {
    return res.status(401).json({
      error: "Session expired or invalid."
    });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }

  next();
}

/* =========================================================
   HELPERS
========================================================= */

function validCoordinate(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value)
  );
}

function haversineDistance(lat1, lon1, lat2, lon2) {
  const earthRadius = 6371000;

  const toRadians = (degrees) =>
    (degrees * Math.PI) / 180;

  const dLat = toRadians(lat2 - lat1);
  const dLon = toRadians(lon2 - lon1);

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRadians(lat1)) *
      Math.cos(toRadians(lat2)) *
      Math.sin(dLon / 2) ** 2;

  const c =
    2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return earthRadius * c;
}

function kenyaDateTime() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Africa/Nairobi",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(new Date());
}

function kenyaDate() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Africa/Nairobi",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(new Date());
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "S.C.A.G.S.S Staff Portal",
    databaseConfigured: configurationReady(),
    time: new Date().toISOString()
  });
});

/* =========================================================
   LOGIN
========================================================= */

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    if (!configurationReady()) {
      return res.status(500).json({
        error: "Server configuration is incomplete."
      });
    }

    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password are required."
      });
    }

    const rows = await supabaseRequest(
      `staff?username=eq.${encodeURIComponent(
        username.trim()
      )}&select=id,username,password_hash,full_name,role,active&limit=1`
    );

    if (!rows || rows.length === 0) {
      return res.status(401).json({
        error: "Invalid username or password."
      });
    }

    const staff = rows[0];

    if (!staff.active) {
      return res.status(403).json({
        error: "This account is inactive."
      });
    }

    const passwordCorrect = await bcrypt.compare(
      password,
      staff.password_hash
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        error: "Invalid username or password."
      });
    }

    const token = createToken(staff);

    res.cookie("scagss_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 12 * 60 * 60 * 1000
    });

    return res.json({
      success: true,
      user: {
        id: staff.id,
        username: staff.username,
        full_name: staff.full_name,
        role: staff.role
      }
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      error: "Login failed."
    });
  }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("scagss_token");

  res.json({
    success: true
  });
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get("/api/me", authenticate, async (req, res) => {
  try {
    const rows = await supabaseRequest(
      `staff?id=eq.${req.user.id}&select=id,username,full_name,role,active&limit=1`
    );

    if (!rows || rows.length === 0 || !rows[0].active) {
      res.clearCookie("scagss_token");

      return res.status(401).json({
        error: "Account unavailable."
      });
    }

    res.json({
      success: true,
      user: rows[0]
    });
  } catch (error) {
    console.error("ME ERROR:", error);

    res.status(500).json({
      error: "Unable to load account."
    });
  }
});

/* =========================================================
   SCHOOL GPS SETTINGS
========================================================= */

async function getSchoolSettings() {
  const rows = await supabaseRequest(
    "school_settings?select=id,latitude,longitude,radius,updated_at&order=id.asc&limit=1"
  );

  if (!rows || rows.length === 0) {
    throw new Error("School GPS settings have not been configured.");
  }

  return rows[0];
}

app.get(
  "/api/settings/gps",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const settings = await getSchoolSettings();

      res.json({
        success: true,
        settings
      });
    } catch (error) {
      console.error("GPS SETTINGS ERROR:", error);

      res.status(500).json({
        error: error.message
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
      const {
        latitude,
        longitude,
        radius
      } = req.body || {};

      if (
        !validCoordinate(latitude) ||
        !validCoordinate(longitude)
      ) {
        return res.status(400).json({
          error: "Valid latitude and longitude are required."
        });
      }

      if (
        latitude < -90 ||
        latitude > 90 ||
        longitude < -180 ||
        longitude > 180
      ) {
        return res.status(400).json({
          error: "Invalid GPS coordinates."
        });
      }

      if (
        typeof radius !== "number" ||
        !Number.isFinite(radius) ||
        radius < 50 ||
        radius > 5000
      ) {
        return res.status(400).json({
          error: "Radius must be between 50 and 5000 metres."
        });
      }

      const current = await getSchoolSettings();

      const updated = await supabaseRequest(
        `school_settings?id=eq.${current.id}`,
        {
          method: "PATCH",
          headers: {
            Prefer: "return=representation"
          },
          body: JSON.stringify({
            latitude,
            longitude,
            radius,
            updated_at: new Date().toISOString()
          })
        }
      );

      res.json({
        success: true,
        settings: updated?.[0] || null
      });
    } catch (error) {
      console.error("UPDATE GPS ERROR:", error);

      res.status(500).json({
        error: "Unable to update GPS settings."
      });
    }
  }
);

/* =========================================================
   CLOCK IN
========================================================= */

app.post(
  "/api/attendance/clock-in",
  authenticate,
  async (req, res) => {
    try {
      if (req.user.role !== "teacher") {
        return res.status(403).json({
          error: "Only teachers can clock in."
        });
      }

      const {
        latitude,
        longitude,
        accuracy
      } = req.body || {};

      if (
        !validCoordinate(latitude) ||
        !validCoordinate(longitude) ||
        typeof accuracy !== "number" ||
        !Number.isFinite(accuracy)
      ) {
        return res.status(400).json({
          error: "Valid GPS coordinates and accuracy are required."
        });
      }

      if (
        latitude < -90 ||
        latitude > 90 ||
        longitude < -180 ||
        longitude > 180
      ) {
        return res.status(400).json({
          error: "Invalid GPS coordinates."
        });
      }

      if (accuracy <= 0 || accuracy > 500) {
        return res.status(400).json({
          error:
            "GPS accuracy is too low. Please move to an open area and try again."
        });
      }

      const settings = await getSchoolSettings();

      const distance = haversineDistance(
        settings.latitude,
        settings.longitude,
        latitude,
        longitude
      );

      if (distance > settings.radius) {
        return res.status(403).json({
          error: "You are outside the school attendance area.",
          distance: Math.round(distance),
          allowedRadius: settings.radius,
          gpsVerified: false
        });
      }

      const today = kenyaDate();
      const now = new Date().toISOString();

      const existing = await supabaseRequest(
        `attendance?staff_id=eq.${req.user.id}&attendance_date=eq.${today}&select=*&limit=1`
      );

      if (existing && existing.length > 0 && existing[0].clock_in) {
        return res.status(409).json({
          error: "You have already clocked in today."
        });
      }

      const localTime = kenyaDateTime().split(", ")[1] || "";
      const hour = Number(localTime.split(":")[0]);

      const status = hour >= 8 ? "Late" : "Present";

      let result;

      if (existing && existing.length > 0) {
        result = await supabaseRequest(
          `attendance?id=eq.${existing[0].id}`,
          {
            method: "PATCH",
            headers: {
              Prefer: "return=representation"
            },
            body: JSON.stringify({
              clock_in: now,
              status,
              gps_verified: true,
              clock_in_lat: latitude,
              clock_in_lon: longitude,
              clock_in_accuracy: accuracy,
              clock_in_distance: distance
            })
          }
        );
      } else {
        result = await supabaseRequest(
          "attendance",
          {
            method: "POST",
            headers: {
              Prefer: "return=representation"
            },
            body: JSON.stringify({
              staff_id: req.user.id,
              attendance_date: today,
              clock_in: now,
              status,
              gps_verified: true,
              clock_in_lat: latitude,
              clock_in_lon: longitude,
              clock_in_accuracy: accuracy,
              clock_in_distance: distance
            })
          }
        );
      }

      res.json({
        success: true,
        message:
          status === "Late"
            ? "Clock-in recorded as Late."
            : "Clock-in recorded successfully.",
        attendance: result?.[0] || null,
        gps: {
          verified: true,
          distance: Math.round(distance),
          accuracy
        }
      });
    } catch (error) {
      console.error("CLOCK IN ERROR:", error);

      res.status(500).json({
        error: "Unable to record clock-in."
      });
    }
  }
);

/* =========================================================
   CLOCK OUT
========================================================= */

app.post(
  "/api/attendance/clock-out",
  authenticate,
  async (req, res) => {
    try {
      if (req.user.role !== "teacher") {
        return res.status(403).json({
          error: "Only teachers can clock out."
        });
      }

      const {
        latitude,
        longitude,
        accuracy
      } = req.body || {};

      if (
        !validCoordinate(latitude) ||
        !validCoordinate(longitude) ||
        typeof accuracy !== "number" ||
        !Number.isFinite(accuracy)
      ) {
        return res.status(400).json({
          error: "Valid GPS coordinates and accuracy are required."
        });
      }

      if (accuracy <= 0 || accuracy > 500) {
        return res.status(400).json({
          error:
            "GPS accuracy is too low. Please try again from an open area."
        });
      }

      const settings = await getSchoolSettings();

      const distance = haversineDistance(
        settings.latitude,
        settings.longitude,
        latitude,
        longitude
      );

      if (distance > settings.radius) {
        return res.status(403).json({
          error: "You are outside the school attendance area.",
          distance: Math.round(distance),
          allowedRadius: settings.radius,
          gpsVerified: false
        });
      }

      const today = kenyaDate();

      const existing = await supabaseRequest(
        `attendance?staff_id=eq.${req.user.id}&attendance_date=eq.${today}&select=*&limit=1`
      );

      if (!existing || existing.length === 0) {
        return res.status(404).json({
          error: "No clock-in record was found for today."
        });
      }

      if (!existing[0].clock_in) {
        return res.status(400).json({
          error: "You must clock in before clocking out."
        });
      }

      if (existing[0].clock_out) {
        return res.status(409).json({
          error: "You have already clocked out today."
        });
      }

      const result = await supabaseRequest(
        `attendance?id=eq.${existing[0].id}`,
        {
          method: "PATCH",
          headers: {
            Prefer: "return=representation"
          },
          body: JSON.stringify({
            clock_out: new Date().toISOString(),
            clock_out_lat: latitude,
            clock_out_lon: longitude,
            clock_out_accuracy: accuracy,
            clock_out_distance: distance
          })
        }
      );

      res.json({
        success: true,
        message: "Clock-out recorded successfully.",
        attendance: result?.[0] || null,
        gps: {
          verified: true,
          distance: Math.round(distance),
          accuracy
        }
      });
    } catch (error) {
      console.error("CLOCK OUT ERROR:", error);

      res.status(500).json({
        error: "Unable to record clock-out."
      });
    }
  }
);

/* =========================================================
   TEACHER ATTENDANCE HISTORY
========================================================= */

app.get(
  "/api/attendance/history",
  authenticate,
  async (req, res) => {
    try {
      const rows = await supabaseRequest(
        `attendance?staff_id=eq.${req.user.id}&select=*&order=attendance_date.desc&limit=100`
      );

      res.json({
        success: true,
        attendance: rows || []
      });
    } catch (error) {
      console.error("HISTORY ERROR:", error);

      res.status(500).json({
        error: "Unable to load attendance history."
      });
    }
  }
);

/* =========================================================
   ADMIN - STAFF
========================================================= */

app.get(
  "/api/admin/staff",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const rows = await supabaseRequest(
        "staff?select=id,username,full_name,role,active,created_at&order=id.asc"
      );

      res.json({
        success: true,
        staff: rows || []
      });
    } catch (error) {
      console.error("STAFF LIST ERROR:", error);

      res.status(500).json({
        error: "Unable to load staff."
      });
    }
  }
);

app.post(
  "/api/admin/staff",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        username,
        password,
        full_name,
        role
      } = req.body || {};

      if (!username || !password || !full_name) {
        return res.status(400).json({
          error:
            "Full name, username and password are required."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error: "Password must contain at least 8 characters."
        });
      }

      const selectedRole =
        role === "admin" ? "admin" : "teacher";

      const existing = await supabaseRequest(
        `staff?username=eq.${encodeURIComponent(
          username.trim()
        )}&select=id&limit=1`
      );

      if (existing && existing.length > 0) {
        return res.status(409).json({
          error: "That username already exists."
        });
      }

      const passwordHash = await bcrypt.hash(
        password,
        12
      );

      const result = await supabaseRequest(
        "staff",
        {
          method: "POST",
          headers: {
            Prefer: "return=representation"
          },
          body: JSON.stringify({
            username: username.trim(),
            password_hash: passwordHash,
            full_name: full_name.trim(),
            role: selectedRole,
            active: true
          })
        }
      );

      res.status(201).json({
        success: true,
        staff: result?.[0] || null
      });
    } catch (error) {
      console.error("CREATE STAFF ERROR:", error);

      res.status(500).json({
        error: "Unable to create staff account."
      });
    }
  }
);

app.patch(
  "/api/admin/staff/:id/status",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          error: "Invalid staff ID."
        });
      }

      const { active } = req.body || {};

      if (typeof active !== "boolean") {
        return res.status(400).json({
          error: "Active status must be true or false."
        });
      }

      if (id === req.user.id && !active) {
        return res.status(400).json({
          error: "You cannot deactivate your own account."
        });
      }

      const result = await supabaseRequest(
        `staff?id=eq.${id}`,
        {
          method: "PATCH",
          headers: {
            Prefer: "return=representation"
          },
          body: JSON.stringify({
            active
          })
        }
      );

      res.json({
        success: true,
        staff: result?.[0] || null
      });
    } catch (error) {
      console.error("STAFF STATUS ERROR:", error);

      res.status(500).json({
        error: "Unable to update staff status."
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
      const today = kenyaDate();

      const rows = await supabaseRequest(
        `attendance?attendance_date=eq.${today}&select=*&order=id.asc`
      );

      res.json({
        success: true,
        attendance: rows || []
      });
    } catch (error) {
      console.error("TODAY ATTENDANCE ERROR:", error);

      res.status(500).json({
        error: "Unable to load today's attendance."
      });
    }
  }
);

/* =========================================================
   ADMIN - GPS TODAY
========================================================= */

app.get(
  "/api/admin/gps/today",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const today = kenyaDate();

      const rows = await supabaseRequest(
        `attendance?attendance_date=eq.${today}&select=*,staff:staff_id(id,username,full_name,role)&order=id.asc`
      );

      res.json({
        success: true,
        attendance: rows || []
      });
    } catch (error) {
      console.error("GPS TODAY ERROR:", error);

      res.status(500).json({
        error: "Unable to load today's GPS records."
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
      const today = kenyaDate();

      const staff = await supabaseRequest(
        "staff?role=eq.teacher&select=id,active"
      );

      const attendance = await supabaseRequest(
        `attendance?attendance_date=eq.${today}&select=id,staff_id,status,clock_in,clock_out`
      );

      const teachers = (staff || []).filter(
        (person) => person.active
      );

      const records = attendance || [];

      const present = records.filter(
        (record) =>
          record.status === "Present"
      ).length;

      const late = records.filter(
        (record) =>
          record.status === "Late"
      ).length;

      const clockedOut = records.filter(
        (record) =>
          Boolean(record.clock_out)
      ).length;

      const absent = Math.max(
        teachers.length - records.length,
        0
      );

      res.json({
        success: true,
        summary: {
          teachers: teachers.length,
          present,
          late,
          clockedOut,
          absent
        }
      });
    } catch (error) {
      console.error("SUMMARY ERROR:", error);

      res.status(500).json({
        error: "Unable to load dashboard summary."
      });
    }
  }
);

/* =========================================================
   ADMIN - SINGLE ATTENDANCE RECORD
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
          error: "Invalid attendance ID."
        });
      }

      const rows = await supabaseRequest(
        `attendance?id=eq.${id}&select=*,staff:staff_id(id,username,full_name,role)&limit=1`
      );

      if (!rows || rows.length === 0) {
        return res.status(404).json({
          error: "Attendance record not found."
        });
      }

      res.json({
        success: true,
        attendance: rows[0]
      });
    } catch (error) {
      console.error("ATTENDANCE RECORD ERROR:", error);

      res.status(500).json({
        error: "Unable to load attendance record."
      });
    }
  }
);

/* =========================================================
   ADMIN REPORT
========================================================= */

app.get(
  "/api/admin/report",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const rows = await supabaseRequest(
        `attendance?select=*,staff:staff_id(id,username,full_name,role)&order=attendance_date.desc&limit=5000`
      );

      res.json({
        success: true,
        report: rows || []
      });
    } catch (error) {
      console.error("REPORT ERROR:", error);

      res.status(500).json({
        error: "Unable to generate report."
      });
    }
  }
);

/* =========================================================
   API 404
========================================================= */

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      error: "API endpoint not found."
    });
  }

  next();
});

/* =========================================================
   GENERAL ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error);

  res.status(500).json({
    error: "Internal server error."
  });
});

/* =========================================================
   VERCEL EXPORT
========================================================= */

module.exports = app;
