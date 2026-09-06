require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");

const app = express();

app.use(helmet());
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_KEY || !JWT_SECRET) {
  console.error("Missing required environment variables.");
}

/* =========================================================
   SUPABASE REST HELPER
========================================================= */

async function supabaseRequest(path, options = {}) {
  const url = `${SUPABASE_URL}/rest/v1/${path}`;

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
    console.error("Supabase error:", response.status, data);

    const error = new Error(
      typeof data === "object" && data?.message
        ? data.message
        : "Database request failed"
    );

    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

/* =========================================================
   AUTH HELPERS
========================================================= */

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role,
      full_name: user.full_name
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function setAuthCookie(res, token) {
  res.cookie("scagss_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function getToken(req) {
  const cookieToken = req.cookies?.scagss_token;

  if (cookieToken) {
    return cookieToken;
  }

  const header = req.headers.authorization || "";

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

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired session."
    });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Administrator access required."
    });
  }

  next();
}

/* =========================================================
   RATE LIMITING
========================================================= */

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many login attempts. Please try again later."
  }
});

/* =========================================================
   GPS DISTANCE
========================================================= */

function calculateDistance(lat1, lon1, lat2, lon2) {
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

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "S.C.A.G.S.S Staff Portal API is running.",
    time: new Date().toISOString()
  });
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const login =
      String(
        req.body.login ||
        req.body.username ||
        req.body.email ||
        ""
      ).trim();

    const password = String(req.body.password || "");

    if (!login || !password) {
      return res.status(400).json({
        success: false,
        message: "Username/email and password are required."
      });
    }

    const encodedLogin = encodeURIComponent(login);

    let users = await supabaseRequest(
      `staff?select=*&username=ilike.${encodedLogin}&limit=1`
    );

    /*
      If username wasn't found, try email.
    */

    if (!users || users.length === 0) {
      users = await supabaseRequest(
        `staff?select=*&email=ilike.${encodedLogin}&limit=1`
      );
    }

    /*
      If still not found, try full name.
    */

    if (!users || users.length === 0) {
      users = await supabaseRequest(
        `staff?select=*&full_name=ilike.${encodedLogin}&limit=1`
      );
    }

    if (!users || users.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details."
      });
    }

    const user = users[0];

    /*
      PENDING TEACHER
    */

    if (user.role !== "admin" && user.active !== true) {
      return res.status(403).json({
        success: false,
        pending: true,
        message:
          "Your registration is pending administrator approval."
      });
    }

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details."
      });
    }

    const token = createToken(user);

    setAuthCookie(res, token);

    return res.json({
      success: true,
      message: "Login successful.",
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        active: user.active
      }
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Server error during login."
    });
  }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("scagss_token");

  res.json({
    success: true,
    message: "Logged out successfully."
  });
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const rows = await supabaseRequest(
      `staff?id=eq.${req.user.id}&select=id,username,full_name,email,phone,role,active,created_at&limit=1`
    );

    if (!rows || rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User account not found."
      });
    }

    res.json({
      success: true,
      user: rows[0]
    });
  } catch (error) {
    console.error("ME ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Unable to load profile."
    });
  }
});

/* =========================================================
   TEACHER SELF REGISTRATION
========================================================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const fullName = String(req.body.full_name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const phone = String(req.body.phone || "").trim();
    const password = String(req.body.password || "");

    if (!fullName || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Full name, email and password are required."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 6 characters."
      });
    }

    /*
      Check email.
    */

    const existingEmail = await supabaseRequest(
      `staff?email=ilike.${encodeURIComponent(email)}&select=id,full_name,active&limit=1`
    );

    if (existingEmail && existingEmail.length > 0) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists."
      });
    }

    /*
      Create a username from the teacher's actual name.
      Example:
      John Paul Omondi -> john.paul.omondi
    */

    const baseUsername = fullName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, ".")
      .replace(/^\.+|\.+$/g, "");

    let username = baseUsername || `teacher${Date.now()}`;

    let suffix = 1;

    while (true) {
      const existingUsername = await supabaseRequest(
        `staff?username=ilike.${encodeURIComponent(username)}&select=id&limit=1`
      );

      if (!existingUsername || existingUsername.length === 0) {
        break;
      }

      suffix++;

      username = `${baseUsername}.${suffix}`;
    }

    const passwordHash = await bcrypt.hash(password, 12);

    /*
      IMPORTANT:
      active = false
      means the teacher is PENDING approval.
    */

    const created = await supabaseRequest("staff", {
      method: "POST",
      headers: {
        Prefer: "return=representation"
      },
      body: JSON.stringify({
        username,
        password_hash: passwordHash,
        full_name: fullName,
        email,
        phone,
        role: "teacher",
        active: false
      })
    });

    return res.status(201).json({
      success: true,
      pending: true,
      message:
        "Registration successful. Your account is pending administrator approval.",
      user: {
        id: created?.[0]?.id,
        full_name: fullName,
        email,
        phone,
        role: "teacher",
        active: false
      }
    });
  } catch (error) {
    console.error("REGISTRATION ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Unable to complete registration."
    });
  }
});

/* =========================================================
   GPS SETTINGS
========================================================= */

app.get("/api/settings/gps", requireAuth, async (req, res) => {
  try {
    const rows = await supabaseRequest(
      "school_settings?select=*&order=id.asc&limit=1"
    );

    if (!rows || rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "GPS settings have not been configured."
      });
    }

    res.json({
      success: true,
      settings: rows[0]
    });
  } catch (error) {
    console.error("GPS SETTINGS ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Unable to load GPS settings."
    });
  }
});

app.put(
  "/api/settings/gps",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const latitude = Number(req.body.latitude);
      const longitude = Number(req.body.longitude);
      const radius = Number(req.body.radius || 500);

      if (
        !Number.isFinite(latitude) ||
        !Number.isFinite(longitude) ||
        !Number.isFinite(radius)
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

      if (existing && existing.length > 0) {
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
        result = await supabaseRequest("school_settings", {
          method: "POST",
          headers: {
            Prefer: "return=representation"
          },
          body: JSON.stringify({
            latitude,
            longitude,
            radius
          })
        });
      }

      res.json({
        success: true,
        message: "GPS settings updated.",
        settings: result?.[0] || null
      });
    } catch (error) {
      console.error("GPS UPDATE ERROR:", error);

      res.status(500).json({
        success: false,
        message: "Unable to update GPS settings."
      });
    }
  }
);

/* =========================================================
   TEACHER CLOCK IN
========================================================= */

app.post("/api/attendance/clock-in", requireAuth, async (req, res) => {
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

    if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
      return res.status(400).json({
        success: false,
        message: "Valid GPS coordinates are required."
      });
    }

    const settingsRows = await supabaseRequest(
      "school_settings?select=*&order=id.asc&limit=1"
    );

    if (!settingsRows || settingsRows.length === 0) {
      return res.status(500).json({
        success: false,
        message: "School GPS location has not been configured."
      });
    }

    const settings = settingsRows[0];

    const distance = calculateDistance(
      lat,
      lon,
      Number(settings.latitude),
      Number(settings.longitude)
    );

    const radius = Number(settings.radius || 500);

    if (distance > radius) {
      return res.status(403).json({
        success: false,
        gps_verified: false,
        distance: Math.round(distance),
        radius,
        message: `You are outside the school attendance zone. Distance: ${Math.round(
          distance
        )} metres.`
      });
    }

    const today = new Date().toISOString().slice(0, 10);

    const existing = await supabaseRequest(
      `attendance?staff_id=eq.${req.user.id}&attendance_date=eq.${today}&select=*&limit=1`
    );

    if (existing && existing.length > 0 && existing[0].clock_in) {
      return res.status(409).json({
        success: false,
        message: "You have already clocked in today.",
        attendance: existing[0]
      });
    }

    const now = new Date().toISOString();

    let attendance;

    if (existing && existing.length > 0) {
      attendance = await supabaseRequest(
        `attendance?id=eq.${existing[0].id}`,
        {
          method: "PATCH",
          headers: {
            Prefer: "return=representation"
          },
          body: JSON.stringify({
            clock_in: now,
            status: "Present",
            gps_verified: true,
            clock_in_lat: lat,
            clock_in_lon: lon,
            clock_in_accuracy: accuracy,
            clock_in_distance: distance
          })
        }
      );
    } else {
      attendance = await supabaseRequest("attendance", {
        method: "POST",
        headers: {
          Prefer: "return=representation"
        },
        body: JSON.stringify({
          staff_id: req.user.id,
          attendance_date: today,
          clock_in: now,
          status: "Present",
          gps_verified: true,
          clock_in_lat: lat,
          clock_in_lon: lon,
          clock_in_accuracy: accuracy,
          clock_in_distance: distance
        })
      });
    }

    res.json({
      success: true,
      message: "Clock-in successful.",
      gps_verified: true,
      distance: Math.round(distance),
      attendance: attendance?.[0] || null
    });
  } catch (error) {
    console.error("CLOCK IN ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Unable to clock in."
    });
  }
});

/* =========================================================
   TEACHER CLOCK OUT
========================================================= */

app.post("/api/attendance/clock-out", requireAuth, async (req, res) => {
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

    if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
      return res.status(400).json({
        success: false,
        message: "Valid GPS coordinates are required."
      });
    }

    const settingsRows = await supabaseRequest(
      "school_settings?select=*&order=id.asc&limit=1"
    );

    if (!settingsRows || settingsRows.length === 0) {
      return res.status(500).json({
        success: false,
        message: "School GPS location has not been configured."
      });
    }

    const settings = settingsRows[0];

    const distance = calculateDistance(
      lat,
      lon,
      Number(settings.latitude),
      Number(settings.longitude)
    );

    const radius = Number(settings.radius || 500);

    if (distance > radius) {
      return res.status(403).json({
        success: false,
        gps_verified: false,
        distance: Math.round(distance),
        radius,
        message: `You are outside the school attendance zone. Distance: ${Math.round(
          distance
        )} metres.`
      });
    }

    const today = new Date().toISOString().slice(0, 10);

    const existing = await supabaseRequest(
      `attendance?staff_id=eq.${req.user.id}&attendance_date=eq.${today}&select=*&limit=1`
    );

    if (!existing || existing.length === 0 || !existing[0].clock_in) {
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

    const updated = await supabaseRequest(
      `attendance?id=eq.${existing[0].id}`,
      {
        method: "PATCH",
        headers: {
          Prefer: "return=representation"
        },
        body: JSON.stringify({
          clock_out: new Date().toISOString(),
          clock_out_lat: lat,
          clock_out_lon: lon,
          clock_out_accuracy: accuracy,
          clock_out_distance: distance
        })
      }
    );

    res.json({
      success: true,
      message: "Clock-out successful.",
      gps_verified: true,
      distance: Math.round(distance),
      attendance: updated?.[0] || null
    });
  } catch (error) {
    console.error("CLOCK OUT ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Unable to clock out."
    });
  }
});

/* =========================================================
   TEACHER TODAY
========================================================= */

app.get("/api/attendance/today", requireAuth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);

    const rows = await supabaseRequest(
      `attendance?staff_id=eq.${req.user.id}&attendance_date=eq.${today}&select=*&limit=1`
    );

    res.json({
      success: true,
      attendance: rows?.[0] || null
    });
  } catch (error) {
    console.error("TODAY ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Unable to load today's attendance."
    });
  }
});

/* =========================================================
   TEACHER HISTORY
========================================================= */

app.get("/api/attendance/history", requireAuth, async (req, res) => {
  try {
    const rows = await supabaseRequest(
      `attendance?staff_id=eq.${req.user.id}&select=*&order=attendance_date.desc&limit=365`
    );

    res.json({
      success: true,
      attendance: rows || []
    });
  } catch (error) {
    console.error("HISTORY ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Unable to load attendance history."
    });
  }
});

/* =========================================================
   ADMIN STAFF LIST
========================================================= */

app.get(
  "/api/admin/staff",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const rows = await supabaseRequest(
        "staff?select=id,username,full_name,email,phone,role,active,created_at&order=id.asc"
      );

      res.json({
        success: true,
        staff: rows || []
      });
    } catch (error) {
      console.error("STAFF LIST ERROR:", error);

      res.status(500).json({
        success: false,
        message: "Unable to load staff."
      });
    }
  }
);

/* =========================================================
   ADMIN APPROVE / DEACTIVATE TEACHER
========================================================= */

app.patch(
  "/api/admin/staff/:id/status",
  requireAuth,
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

      const updated = await supabaseRequest(
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
        message: active
          ? "Staff member approved successfully."
          : "Staff member deactivated.",
        staff: updated?.[0] || null
      });
    } catch (error) {
      console.error("STATUS ERROR:", error);

      res.status(500).json({
        success: false,
        message: "Unable to update staff status."
      });
    }
  }
);

/* =========================================================
   ADMIN UPDATE STAFF PROFILE
========================================================= */

app.patch(
  "/api/admin/staff/:id",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      const updates = {};

      if (req.body.full_name !== undefined) {
        updates.full_name = String(req.body.full_name).trim();
      }

      if (req.body.email !== undefined) {
        updates.email = String(req.body.email).trim().toLowerCase();
      }

      if (req.body.phone !== undefined) {
        updates.phone = String(req.body.phone).trim();
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          success: false,
          message: "No profile changes supplied."
        });
      }

      const updated = await supabaseRequest(
        `staff?id=eq.${id}`,
        {
          method: "PATCH",
          headers: {
            Prefer: "return=representation"
          },
          body: JSON.stringify(updates)
        }
      );

      res.json({
        success: true,
        message: "Staff profile updated.",
        staff: updated?.[0] || null
      });
    } catch (error) {
      console.error("PROFILE UPDATE ERROR:", error);

      res.status(500).json({
        success: false,
        message: "Unable to update staff profile."
      });
    }
  }
);

/* =========================================================
   ADMIN PASSWORD RESET
========================================================= */

app.patch(
  "/api/admin/staff/:id/password",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);
      const password = String(req.body.password || "");

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
          headers: {
            Prefer: "return=minimal"
          },
          body: JSON.stringify({
            password_hash: passwordHash
          })
        }
      );

      res.json({
        success: true,
        message: "Password reset successfully."
      });
    } catch (error) {
      console.error("PASSWORD RESET ERROR:", error);

      res.status(500).json({
        success: false,
        message: "Unable to reset password."
      });
    }
  }
);

/* =========================================================
   ADMIN TODAY ATTENDANCE
========================================================= */

app.get(
  "/api/admin/attendance/today",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const today = new Date().toISOString().slice(0, 10);

      const rows = await supabaseRequest(
        `attendance?attendance_date=eq.${today}&select=*,staff(id,username,full_name,email,phone,role)&order=clock_in.asc`
      );

      res.json({
        success: true,
        date: today,
        attendance: rows || []
      });
    } catch (error) {
      console.error("ADMIN ATTENDANCE ERROR:", error);

      res.status(500).json({
        success: false,
        message: "Unable to load today's attendance."
      });
    }
  }
);

/* =========================================================
   ADMIN GPS MONITOR
========================================================= */

app.get(
  "/api/admin/gps/today",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const today = new Date().toISOString().slice(0, 10);

      const rows = await supabaseRequest(
        `attendance?attendance_date=eq.${today}&select=id,staff_id,attendance_date,clock_in,clock_out,gps_verified,clock_in_lat,clock_in_lon,clock_in_accuracy,clock_in_distance,clock_out_lat,clock_out_lon,clock_out_accuracy,clock_out_distance,staff(full_name,email,phone)&order=clock_in.desc`
      );

      res.json({
        success: true,
        gps: rows || []
      });
    } catch (error) {
      console.error("GPS MONITOR ERROR:", error);

      res.status(500).json({
        success: false,
        message: "Unable to load GPS records."
      });
    }
  }
);

/* =========================================================
   ADMIN SUMMARY
========================================================= */

app.get(
  "/api/admin/summary",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const staff = await supabaseRequest(
        "staff?select=id,role,active"
      );

      const today = new Date().toISOString().slice(0, 10);

      const attendance = await supabaseRequest(
        `attendance?attendance_date=eq.${today}&select=id,staff_id,clock_in,clock_out,gps_verified`
      );

      const teachers = (staff || []).filter(
        x => x.role === "teacher"
      );

      const activeTeachers = teachers.filter(
        x => x.active === true
      );

      const pendingTeachers = teachers.filter(
        x => x.active !== true
      );

      const checkedIn = (attendance || []).filter(
        x => x.clock_in
      );

      const checkedOut = (attendance || []).filter(
        x => x.clock_out
      );

      res.json({
        success: true,
        summary: {
          total_staff: teachers.length,
          active_staff: activeTeachers.length,
          pending_staff: pendingTeachers.length,
          checked_in: checkedIn.length,
          checked_out: checkedOut.length,
          gps_verified: (attendance || []).filter(
            x => x.gps_verified
          ).length
        }
      });
    } catch (error) {
      console.error("SUMMARY ERROR:", error);

      res.status(500).json({
        success: false,
        message: "Unable to load dashboard summary."
      });
    }
  }
);

/* =========================================================
   INDIVIDUAL STAFF REPORT
========================================================= */

app.get(
  "/api/admin/report",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const staffId = Number(req.query.staff_id);
      const from = String(req.query.from || "");
      const to = String(req.query.to || "");

      if (!Number.isInteger(staffId)) {
        return res.status(400).json({
          success: false,
          message: "Valid staff_id is required."
        });
      }

      let query =
        `attendance?staff_id=eq.${staffId}&select=*,staff(id,username,full_name,email,phone,role)&order=attendance_date.desc`;

      if (from) {
        query += `&attendance_date=gte.${encodeURIComponent(from)}`;
      }

      if (to) {
        query += `&attendance_date=lte.${encodeURIComponent(to)}`;
      }

      const rows = await supabaseRequest(query);

      res.json({
        success: true,
        staff: rows?.[0]?.staff || null,
        attendance: rows || []
      });
    } catch (error) {
      console.error("REPORT ERROR:", error);

      res.status(500).json({
        success: false,
        message: "Unable to generate report."
      });
    }
  }
);

/* =========================================================
   AI ASSISTANT
========================================================= */

app.post(
  "/api/ai/assistant",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const question = String(req.body.question || "").trim();

      if (!question) {
        return res.status(400).json({
          success: false,
          message: "Please provide a question."
        });
      }

      /*
        AI provider connection can be added here later.
        The attendance system itself does not depend on AI.
      */

      res.json({
        success: true,
        answer:
          "The S.C.A.G.S.S AI Assistant is connected to the portal. AI analysis can be connected to a secure AI provider without exposing your database credentials."
      });
    } catch (error) {
      console.error("AI ERROR:", error);

      res.status(500).json({
        success: false,
        message: "AI Assistant is temporarily unavailable."
      });
    }
  }
);

/* =========================================================
   API 404
========================================================= */

app.use("/api", (req, res) => {
  res.status(404).json({
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

  res.status(500).json({
    success: false,
    message: "Internal server error."
  });
});

/*
  IMPORTANT FOR VERCEL:
  Do NOT use app.listen().
*/

module.exports = app;
