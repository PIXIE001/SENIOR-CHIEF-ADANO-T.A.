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
    crossOriginResourcePolicy: false
  })
);

app.use(
  cors({
    origin: process.env.FRONTEND_URL || true,
    credentials: true
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

const actionLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !JWT_SECRET) {
  console.error("Missing required environment variables.");
}

/* =========================================================
   BASIC HELPERS
========================================================= */

function jsonError(res, status, message) {
  return res.status(status).json({
    success: false,
    message
  });
}

function kenyaDate() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Africa/Nairobi",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).format(new Date());
}

function kenyaHour() {
  return Number(
    new Intl.DateTimeFormat("en-GB", {
      timeZone: "Africa/Nairobi",
      hour: "2-digit",
      hour12: false
    }).format(new Date())
  );
}

function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371000;

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

  return R * c;
}

function validGPS(latitude, longitude, accuracy) {
  return (
    typeof latitude === "number" &&
    typeof longitude === "number" &&
    typeof accuracy === "number" &&
    Number.isFinite(latitude) &&
    Number.isFinite(longitude) &&
    Number.isFinite(accuracy) &&
    latitude >= -90 &&
    latitude <= 90 &&
    longitude >= -180 &&
    longitude <= 180 &&
    accuracy >= 0
  );
}

/* =========================================================
   SUPABASE REST
========================================================= */

async function supabaseRequest(path, options = {}) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("Supabase environment variables are missing.");
  }

  const cleanBase = SUPABASE_URL.replace(/\/+$/, "");

  const url = `${cleanBase}/rest/v1/${path}`;

  const response = await fetch(url, {
    ...options,
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const text = await response.text();

  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!response.ok) {
    console.error("SUPABASE ERROR:", response.status, data);

    const error = new Error(
      typeof data === "object" && data?.message
        ? data.message
        : "Supabase request failed."
    );

    error.status = response.status;
    throw error;
  }

  return data;
}

/* =========================================================
   AUTH
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
    const token = req.cookies?.scagss_token;

    if (!token) {
      return jsonError(res, 401, "Authentication required.");
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch {
    return jsonError(res, 401, "Session expired. Please log in again.");
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return jsonError(res, 403, "Administrator access required.");
  }

  next();
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "S.C.A.G.S.S Staff Portal",
    databaseConfigured: Boolean(
      SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
    ),
    time: new Date().toISOString()
  });
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");

    if (!username || !password) {
      return jsonError(
        res,
        400,
        "Username and password are required."
      );
    }

    const rows = await supabaseRequest(
      `staff?username=eq.${encodeURIComponent(
        username
      )}&select=id,username,password_hash,full_name,role,active&limit=1`
    );

    const staff = rows?.[0];

    if (!staff) {
      return jsonError(res, 401, "Invalid username or password.");
    }

    if (!staff.active) {
      return jsonError(
        res,
        403,
        "This staff account is inactive."
      );
    }

    const passwordCorrect = await bcrypt.compare(
      password,
      staff.password_hash
    );

    if (!passwordCorrect) {
      return jsonError(res, 401, "Invalid username or password.");
    }

    const token = createToken(staff);

    res.cookie("scagss_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 12 * 60 * 60 * 1000,
      path: "/"
    });

    return res.json({
      success: true,
      message: "Login successful.",
      user: {
        id: staff.id,
        username: staff.username,
        full_name: staff.full_name,
        role: staff.role
      }
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return jsonError(
      res,
      500,
      "Unable to log in at the moment."
    );
  }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/auth/logout", authenticate, (req, res) => {
  res.clearCookie("scagss_token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/"
  });

  res.json({
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
      `staff?id=eq.${encodeURIComponent(
        req.user.id
      )}&select=id,username,full_name,role,active&limit=1`
    );

    const staff = rows?.[0];

    if (!staff || !staff.active) {
      res.clearCookie("scagss_token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/"
      });

      return jsonError(
        res,
        401,
        "Your account is no longer active."
      );
    }

    return res.json({
      success: true,
      user: staff
    });
  } catch (error) {
    console.error("ME ERROR:", error);
    return jsonError(res, 500, "Unable to load account.");
  }
});

/* =========================================================
   GPS SCHOOL SETTINGS
========================================================= */

app.get(
  "/api/settings/gps",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const rows = await supabaseRequest(
        "school_settings?select=id,latitude,longitude,radius,updated_at&order=id.asc&limit=1"
      );

      return res.json({
        success: true,
        settings: rows?.[0] || null
      });
    } catch (error) {
      console.error("GPS SETTINGS ERROR:", error);
      return jsonError(
        res,
        500,
        "Unable to load GPS settings."
      );
    }
  }
);

app.put(
  "/api/settings/gps",
  authenticate,
  requireAdmin,
  actionLimiter,
  async (req, res) => {
    try {
      const latitude = Number(req.body?.latitude);
      const longitude = Number(req.body?.longitude);
      const radius = Number(req.body?.radius);

      if (
        !Number.isFinite(latitude) ||
        !Number.isFinite(longitude) ||
        !Number.isFinite(radius)
      ) {
        return jsonError(
          res,
          400,
          "Valid GPS settings are required."
        );
      }

      if (
        latitude < -90 ||
        latitude > 90 ||
        longitude < -180 ||
        longitude > 180
      ) {
        return jsonError(
          res,
          400,
          "Invalid latitude or longitude."
        );
      }

      if (radius < 50 || radius > 5000) {
        return jsonError(
          res,
          400,
          "GPS radius must be between 50 and 5000 metres."
        );
      }

      const existing = await supabaseRequest(
        "school_settings?select=id&order=id.asc&limit=1"
      );

      let result;

      if (existing?.length) {
        result = await supabaseRequest(
          `school_settings?id=eq.${existing[0].id}`,
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
      } else {
        result = await supabaseRequest(
          "school_settings",
          {
            method: "POST",
            headers: {
              Prefer: "return=representation"
            },
            body: JSON.stringify({
              latitude,
              longitude,
              radius
            })
          }
        );
      }

      return res.json({
        success: true,
        message: "GPS settings saved.",
        settings: result?.[0] || null
      });
    } catch (error) {
      console.error("GPS SAVE ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to save GPS settings."
      );
    }
  }
);

/* =========================================================
   GET TODAY'S ATTENDANCE FOR STAFF
========================================================= */

app.get(
  "/api/attendance/today",
  authenticate,
  async (req, res) => {
    try {
      const date = kenyaDate();

      const rows = await supabaseRequest(
        `attendance?staff_id=eq.${encodeURIComponent(
          req.user.id
        )}&attendance_date=eq.${encodeURIComponent(
          date
        )}&select=id,staff_id,attendance_date,clock_in,clock_out,status,gps_verified,clock_in_lat,clock_in_lon,clock_in_accuracy,clock_in_distance,clock_out_lat,clock_out_lon,clock_out_accuracy,clock_out_distance&limit=1`
      );

      return res.json({
        success: true,
        attendance: rows?.[0] || null
      });
    } catch (error) {
      console.error("TODAY ATTENDANCE ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to load today's attendance."
      );
    }
  }
);

/* =========================================================
   CLOCK IN
========================================================= */

app.post(
  "/api/attendance/clock-in",
  authenticate,
  actionLimiter,
  async (req, res) => {
    try {
      if (req.user.role === "admin") {
        return jsonError(
          res,
          403,
          "Administrators do not use staff attendance clock-in."
        );
      }

      const latitude = Number(req.body?.latitude);
      const longitude = Number(req.body?.longitude);
      const accuracy = Number(req.body?.accuracy);

      /* -----------------------------------------------
         GPS VALIDATION
      ------------------------------------------------ */

      if (!validGPS(latitude, longitude, accuracy)) {
        return jsonError(
          res,
          400,
          "Valid GPS coordinates and accuracy are required."
        );
      }

      /* -----------------------------------------------
         LOAD SCHOOL GPS
      ------------------------------------------------ */

      const settingsRows = await supabaseRequest(
        "school_settings?select=id,latitude,longitude,radius&order=id.asc&limit=1"
      );

      const settings = settingsRows?.[0];

      if (!settings) {
        return jsonError(
          res,
          500,
          "School GPS settings have not been configured."
        );
      }

      const distance = calculateDistance(
        latitude,
        longitude,
        Number(settings.latitude),
        Number(settings.longitude)
      );

      /* -----------------------------------------------
         GPS ACCURACY CHECK
      ------------------------------------------------ */

      if (accuracy > 500) {
        return jsonError(
          res,
          400,
          `GPS accuracy is too low (${Math.round(
            accuracy
          )} metres). Please enable precise location and try again.`
        );
      }

      /* -----------------------------------------------
         SCHOOL GEOFENCE
      ------------------------------------------------ */

      if (distance > Number(settings.radius)) {
        return jsonError(
          res,
          403,
          `You are outside the school attendance area. Your distance is approximately ${Math.round(
            distance
          )} metres.`
        );
      }

      const date = kenyaDate();

      /* -----------------------------------------------
         CHECK EXISTING ATTENDANCE
      ------------------------------------------------ */

      const existingRows = await supabaseRequest(
        `attendance?staff_id=eq.${encodeURIComponent(
          req.user.id
        )}&attendance_date=eq.${encodeURIComponent(
          date
        )}&select=id,clock_in,clock_out,status,gps_verified&limit=1`
      );

      const existing = existingRows?.[0];

      if (existing) {
        if (existing.clock_in) {
          return jsonError(
            res,
            409,
            `You are already clocked in today at ${new Date(
              existing.clock_in
            ).toLocaleTimeString("en-KE", {
              timeZone: "Africa/Nairobi",
              hour: "2-digit",
              minute: "2-digit",
              hour12: true
            })}.`
          );
        }
      }

      /* -----------------------------------------------
         ATTENDANCE STATUS
         8:00 AM OR LATER = LATE
      ------------------------------------------------ */

      const status = kenyaHour() >= 8 ? "Late" : "Present";

      const now = new Date().toISOString();

      let result;

      if (existing) {
        result = await supabaseRequest(
          `attendance?id=eq.${existing.id}`,
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
              attendance_date: date,
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

      return res.json({
        success: true,
        message: "Clock-in successful.",
        attendance: result?.[0] || null
      });
    } catch (error) {
      console.error("CLOCK-IN ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to complete clock-in."
      );
    }
  }
);

/* =========================================================
   CLOCK OUT
========================================================= */

app.post(
  "/api/attendance/clock-out",
  authenticate,
  actionLimiter,
  async (req, res) => {
    try {
      if (req.user.role === "admin") {
        return jsonError(
          res,
          403,
          "Administrators do not use staff attendance clock-out."
        );
      }

      const latitude = Number(req.body?.latitude);
      const longitude = Number(req.body?.longitude);
      const accuracy = Number(req.body?.accuracy);

      if (!validGPS(latitude, longitude, accuracy)) {
        return jsonError(
          res,
          400,
          "Valid GPS coordinates and accuracy are required."
        );
      }

      const settingsRows = await supabaseRequest(
        "school_settings?select=id,latitude,longitude,radius&order=id.asc&limit=1"
      );

      const settings = settingsRows?.[0];

      if (!settings) {
        return jsonError(
          res,
          500,
          "School GPS settings have not been configured."
        );
      }

      const distance = calculateDistance(
        latitude,
        longitude,
        Number(settings.latitude),
        Number(settings.longitude)
      );

      if (accuracy > 500) {
        return jsonError(
          res,
          400,
          `GPS accuracy is too low (${Math.round(
            accuracy
          )} metres). Please enable precise location and try again.`
        );
      }

      if (distance > Number(settings.radius)) {
        return jsonError(
          res,
          403,
          `You are outside the school attendance area. Your distance is approximately ${Math.round(
            distance
          )} metres.`
        );
      }

      const date = kenyaDate();

      const rows = await supabaseRequest(
        `attendance?staff_id=eq.${encodeURIComponent(
          req.user.id
        )}&attendance_date=eq.${encodeURIComponent(
          date
        )}&select=id,clock_in,clock_out,status,gps_verified&limit=1`
      );

      const attendance = rows?.[0];

      if (!attendance || !attendance.clock_in) {
        return jsonError(
          res,
          400,
          "You must clock in before you can clock out."
        );
      }

      if (attendance.clock_out) {
        return jsonError(
          res,
          409,
          "You have already clocked out today."
        );
      }

      const result = await supabaseRequest(
        `attendance?id=eq.${attendance.id}`,
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

      return res.json({
        success: true,
        message: "Clock-out successful.",
        attendance: result?.[0] || null
      });
    } catch (error) {
      console.error("CLOCK-OUT ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to complete clock-out."
      );
    }
  }
);

/* =========================================================
   STAFF ATTENDANCE HISTORY
========================================================= */

app.get(
  "/api/attendance/history",
  authenticate,
  async (req, res) => {
    try {
      const rows = await supabaseRequest(
        `attendance?staff_id=eq.${encodeURIComponent(
          req.user.id
        )}&select=id,attendance_date,clock_in,clock_out,status,gps_verified,clock_in_lat,clock_in_lon,clock_in_accuracy,clock_in_distance,clock_out_lat,clock_out_lon,clock_out_accuracy,clock_out_distance&order=attendance_date.desc&limit=100`
      );

      return res.json({
        success: true,
        attendance: rows || []
      });
    } catch (error) {
      console.error("HISTORY ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to load attendance history."
      );
    }
  }
);

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
        "staff?select=id,username,full_name,role,active,created_at&order=full_name.asc"
      );

      return res.json({
        success: true,
        staff: rows || []
      });
    } catch (error) {
      console.error("ADMIN STAFF ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to load staff."
      );
    }
  }
);

/* =========================================================
   ADMIN - ADD STAFF
========================================================= */

app.post(
  "/api/admin/staff",
  authenticate,
  requireAdmin,
  actionLimiter,
  async (req, res) => {
    try {
      const fullName = String(
        req.body?.full_name || ""
      ).trim();

      const username = String(
        req.body?.username || ""
      ).trim();

      const password = String(
        req.body?.password || ""
      );

      const role =
        req.body?.role === "admin"
          ? "admin"
          : "teacher";

      if (!fullName || !username || !password) {
        return jsonError(
          res,
          400,
          "Full name, username and password are required."
        );
      }

      if (password.length < 8) {
        return jsonError(
          res,
          400,
          "Password must be at least 8 characters."
        );
      }

      const existing = await supabaseRequest(
        `staff?username=eq.${encodeURIComponent(
          username
        )}&select=id&limit=1`
      );

      if (existing?.length) {
        return jsonError(
          res,
          409,
          "That username already exists."
        );
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
            username,
            password_hash: passwordHash,
            full_name: fullName,
            role,
            active: true
          })
        }
      );

      return res.status(201).json({
        success: true,
        message: "Staff account created.",
        staff: result?.[0] || null
      });
    } catch (error) {
      console.error("CREATE STAFF ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to create staff account."
      );
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
  actionLimiter,
  async (req, res) => {
    try {
      const id = Number(req.params.id);
      const active = Boolean(req.body?.active);

      if (!Number.isInteger(id)) {
        return jsonError(res, 400, "Invalid staff ID.");
      }

      if (id === Number(req.user.id)) {
        return jsonError(
          res,
          400,
          "You cannot deactivate your own administrator account."
        );
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

      return res.json({
        success: true,
        message: active
          ? "Staff account activated."
          : "Staff account deactivated.",
        staff: result?.[0] || null
      });
    } catch (error) {
      console.error("STAFF STATUS ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to update staff status."
      );
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
      const date = kenyaDate();

      const rows = await supabaseRequest(
        `attendance?attendance_date=eq.${encodeURIComponent(
          date
        )}&select=id,staff_id,attendance_date,clock_in,clock_out,status,gps_verified,clock_in_lat,clock_in_lon,clock_in_accuracy,clock_in_distance,clock_out_lat,clock_out_lon,clock_out_accuracy,clock_out_distance,staff:staff_id(id,username,full_name,role)&order=clock_in.asc`
      );

      return res.json({
        success: true,
        date,
        attendance: rows || []
      });
    } catch (error) {
      console.error("ADMIN TODAY ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to load today's attendance."
      );
    }
  }
);

/* =========================================================
   ADMIN - LIVE GPS / ATTENDANCE
========================================================= */

app.get(
  "/api/admin/gps/today",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const date = kenyaDate();

      const rows = await supabaseRequest(
        `attendance?attendance_date=eq.${encodeURIComponent(
          date
        )}&select=id,staff_id,attendance_date,clock_in,clock_out,status,gps_verified,clock_in_lat,clock_in_lon,clock_in_accuracy,clock_in_distance,clock_out_lat,clock_out_lon,clock_out_accuracy,clock_out_distance,staff:staff_id(id,username,full_name,role)&order=clock_in.desc`
      );

      return res.json({
        success: true,
        date,
        attendance: rows || []
      });
    } catch (error) {
      console.error("ADMIN GPS ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to load live GPS attendance."
      );
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
      const date = kenyaDate();

      const staffRows = await supabaseRequest(
        "staff?active=eq.true&role=eq.teacher&select=id"
      );

      const attendanceRows = await supabaseRequest(
        `attendance?attendance_date=eq.${encodeURIComponent(
          date
        )}&select=id,staff_id,clock_in,clock_out,status`
      );

      const totalTeachers = staffRows?.length || 0;
      const attendance = attendanceRows || [];

      const present = attendance.filter(
        (item) =>
          item.clock_in &&
          item.status === "Present"
      ).length;

      const late = attendance.filter(
        (item) =>
          item.clock_in &&
          item.status === "Late"
      ).length;

      const clockedOut = attendance.filter(
        (item) => item.clock_out
      ).length;

      const absent = Math.max(
        0,
        totalTeachers - attendance.length
      );

      return res.json({
        success: true,
        date,
        summary: {
          total_teachers: totalTeachers,
          present,
          late,
          clocked_out: clockedOut,
          absent
        }
      });
    } catch (error) {
      console.error("ADMIN SUMMARY ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to load dashboard summary."
      );
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
        return jsonError(
          res,
          400,
          "Invalid attendance ID."
        );
      }

      const rows = await supabaseRequest(
        `attendance?id=eq.${id}&select=id,staff_id,attendance_date,clock_in,clock_out,status,gps_verified,clock_in_lat,clock_in_lon,clock_in_accuracy,clock_in_distance,clock_out_lat,clock_out_lon,clock_out_accuracy,clock_out_distance,staff:staff_id(id,username,full_name,role)&limit=1`
      );

      if (!rows?.length) {
        return jsonError(
          res,
          404,
          "Attendance record not found."
        );
      }

      return res.json({
        success: true,
        attendance: rows[0]
      });
    } catch (error) {
      console.error("ADMIN ATTENDANCE ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to load attendance record."
      );
    }
  }
);

/* =========================================================
   ADMIN - REPORT
========================================================= */

app.get(
  "/api/admin/report",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const rows = await supabaseRequest(
        "attendance?select=id,attendance_date,clock_in,clock_out,status,gps_verified,clock_in_lat,clock_in_lon,clock_in_accuracy,clock_in_distance,clock_out_lat,clock_out_lon,clock_out_accuracy,clock_out_distance,staff:staff_id(username,full_name,role)&order=attendance_date.desc,clock_in.desc&limit=5000"
      );

      return res.json({
        success: true,
        report: rows || []
      });
    } catch (error) {
      console.error("REPORT ERROR:", error);

      return jsonError(
        res,
        500,
        "Unable to generate report."
      );
    }
  }
);

/* =========================================================
   API 404
========================================================= */

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) {
    return jsonError(
      res,
      404,
      "API endpoint not found."
    );
  }

  next();
});

/* =========================================================
   GENERAL ERROR
========================================================= */

app.use((error, req, res, next) => {
  console.error("GENERAL ERROR:", error);

  if (res.headersSent) {
    return next(error);
  }

  return jsonError(
    res,
    500,
    "An unexpected server error occurred."
  );
});

/* =========================================================
   VERCEL EXPORT
========================================================= */

module.exports = app;
