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

const SUPABASE_URL =
(process.env.SUPABASE_URL || "").replace(//+$/, "");

const SUPABASE_SERVICE_ROLE_KEY =
process.env.SUPABASE_SERVICE_ROLE_KEY || "";

const JWT_SECRET =
process.env.JWT_SECRET || "";

const FRONTEND_URL =
process.env.FRONTEND_URL || "";

const SCHOOL_TIMEZONE =
"Africa/Nairobi";

const DEFAULT_RADIUS =
500;

/* =========================================================
SECURITY / MIDDLEWARE
========================================================= */

app.use(
helmet({
crossOriginResourcePolicy: false
})
);

app.use(
cors({
origin: FRONTEND_URL || true,
credentials: true
})
);

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

const loginLimiter = rateLimit({
windowMs: 15 * 60 * 1000,
limit: 30,
standardHeaders: true,
legacyHeaders: false,
message: {
success: false,
message: "Too many login attempts. Please try again later."
}
});

app.use("/api/auth/login", loginLimiter);

/* =========================================================
BASIC CHECKS
========================================================= */

function databaseReady() {
return Boolean(
SUPABASE_URL &&
SUPABASE_SERVICE_ROLE_KEY
);
}

function jwtReady() {
return Boolean(JWT_SECRET);
}

/* =========================================================
SUPABASE REST
========================================================= */

async function supabaseRequest(
path,
options = {}
) {

if (!databaseReady()) {
throw new Error(
"Database environment variables are not configured."
);
}

const url =
"${SUPABASE_URL}/rest/v1/${path}";

const response =
await fetch(url, {
...options,
headers: {
apikey:
SUPABASE_SERVICE_ROLE_KEY,

    Authorization:
      `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,

    "Content-Type":
      "application/json",

    Prefer:
      options.prefer ||
      "return=representation",

    ...(options.headers || {})
  }
});

const text =
await response.text();

let data = null;

try {
data = text
? JSON.parse(text)
: null;
} catch {
data = text;
}

if (!response.ok) {

console.error(
  "Supabase error:",
  response.status,
  data
);

const errorMessage =
  data?.message ||
  data?.hint ||
  data?.details ||
  data?.error ||
  `Database request failed (${response.status})`;

const error =
  new Error(errorMessage);

error.status =
  response.status;

throw error;

}

return data;
}

/* =========================================================
DATE / TIME
========================================================= */

function getKenyaDate() {

return new Intl.DateTimeFormat(
"en-CA",
{
timeZone: SCHOOL_TIMEZONE,
year: "numeric",
month: "2-digit",
day: "2-digit"
}
).format(new Date());

}

function getKenyaHour() {

return Number(
new Intl.DateTimeFormat(
"en-US",
{
timeZone: SCHOOL_TIMEZONE,
hour: "2-digit",
hour12: false
}
).format(new Date())
);

}

/* =========================================================
GPS
========================================================= */

function isValidGPS(
latitude,
longitude,
accuracy
) {

return (
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

function haversineDistance(
lat1,
lon1,
lat2,
lon2
) {

const R = 6371000;

const toRad =
degrees =>
degrees * Math.PI / 180;

const dLat =
toRad(lat2 - lat1);

const dLon =
toRad(lon2 - lon1);

const a =
Math.sin(dLat / 2) ** 2 +
Math.cos(toRad(lat1)) *
Math.cos(toRad(lat2)) *
Math.sin(dLon / 2) ** 2;

const c =
2 * Math.atan2(
Math.sqrt(a),
Math.sqrt(1 - a)
);

return R * c;

}

/* =========================================================
JWT
========================================================= */

function createToken(user) {

if (!jwtReady()) {
throw new Error(
"JWT_SECRET is not configured."
);
}

return jwt.sign(
{
id: user.id,
username: user.username,
role: user.role
},
JWT_SECRET,
{
expiresIn: "8h"
}
);

}

function setAuthCookie(
res,
token
) {

res.cookie(
"scagss_token",
token,
{
httpOnly: true,
secure:
process.env.NODE_ENV === "production",
sameSite: "lax",
maxAge:
8 * 60 * 60 * 1000,
path: "/"
}
);

}

function clearAuthCookie(res) {

res.clearCookie(
"scagss_token",
{
httpOnly: true,
secure:
process.env.NODE_ENV === "production",
sameSite: "lax",
path: "/"
}
);

}

/* =========================================================
AUTH MIDDLEWARE
========================================================= */

function authenticate(
req,
res,
next
) {

try {

const token =
  req.cookies?.scagss_token;

if (!token) {

  return res.status(401).json({
    success: false,
    message: "Authentication required."
  });

}

if (!jwtReady()) {

  return res.status(500).json({
    success: false,
    message: "JWT authentication is not configured."
  });

}

const decoded =
  jwt.verify(
    token,
    JWT_SECRET
  );

req.user =
  decoded;

next();

} catch {

return res.status(401).json({
  success: false,
  message: "Session expired. Please log in again."
});

}

}

function requireAdmin(
req,
res,
next
) {

if (
!req.user ||
req.user.role !== "admin"
) {

return res.status(403).json({
  success: false,
  message: "Administrator access required."
});

}

next();

}

function requireTeacher(
req,
res,
next
) {

if (
!req.user ||
req.user.role !== "teacher"
) {

return res.status(403).json({
  success: false,
  message: "Teacher access required."
});

}

next();

}

/* =========================================================
HEALTH
========================================================= */

app.get(
"/api/health",
async (req, res) => {

res.json({
  success: true,
  service:
    "S.C.A.G.S.S Staff Portal",
  databaseConfigured:
    databaseReady(),
  time:
    new Date().toISOString()
});

}
);

/* =========================================================
LOGIN
========================================================= */

app.post(
"/api/auth/login",
async (req, res) => {

try {

  const {
    username,
    password
  } = req.body || {};

  if (
    typeof username !== "string" ||
    typeof password !== "string" ||
    !username.trim() ||
    !password
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Username and password are required."
    });

  }

  const cleanUsername =
    username.trim();

  const rows =
    await supabaseRequest(
      `staff?select=id,username,password_hash,full_name,email,phone,role,active,created_at&username=eq.${encodeURIComponent(cleanUsername)}&limit=1`,
      {
        method: "GET"
      }
    );

  if (
    !Array.isArray(rows) ||
    rows.length === 0
  ) {

    return res.status(401).json({
      success: false,
      message:
        "Invalid username or password."
    });

  }

  const user =
    rows[0];

  if (!user.active) {

    return res.status(403).json({
      success: false,
      message:
        "This account has been deactivated."
    });

  }

  const valid =
    await bcrypt.compare(
      password,
      user.password_hash
    );

  if (!valid) {

    return res.status(401).json({
      success: false,
      message:
        "Invalid username or password."
    });

  }

  const token =
    createToken(user);

  setAuthCookie(
    res,
    token
  );

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

  console.error(
    "Login error:",
    error
  );

  return res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message ||
      "Login failed."
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

clearAuthCookie(res);

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
      `staff?select=id,username,full_name,email,phone,role,active,created_at&id=eq.${encodeURIComponent(req.user.id)}&limit=1`,
      {
        method: "GET"
      }
    );

  if (
    !Array.isArray(rows) ||
    !rows.length
  ) {

    return res.status(404).json({
      success: false,
      message:
        "User account not found."
    });

  }

  res.json({
    success: true,
    user: rows[0]
  });

} catch (error) {

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
  });

}

}
);

/* =========================================================
GPS SETTINGS - GET
========================================================= */

app.get(
"/api/settings/gps",
authenticate,
requireAdmin,
async (req, res) => {

try {

  const rows =
    await supabaseRequest(
      "school_settings?select=id,latitude,longitude,radius,updated_at&order=id.asc&limit=1",
      {
        method: "GET"
      }
    );

  if (
    !Array.isArray(rows) ||
    !rows.length
  ) {

    return res.json({
      success: true,
      settings: {
        latitude: null,
        longitude: null,
        radius:
          DEFAULT_RADIUS
      }
    });

  }

  res.json({
    success: true,
    settings:
      rows[0]
  });

} catch (error) {

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
  });

}

}
);

/* =========================================================
GPS SETTINGS - UPDATE
========================================================= */

app.put(
"/api/settings/gps",
authenticate,
requireAdmin,
async (req, res) => {

try {

  const latitude =
    Number(req.body?.latitude);

  const longitude =
    Number(req.body?.longitude);

  const radius =
    Number(req.body?.radius);

  if (
    !Number.isFinite(latitude) ||
    !Number.isFinite(longitude) ||
    !Number.isFinite(radius)
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Latitude, longitude and radius must be valid numbers."
    });

  }

  if (
    latitude < -90 ||
    latitude > 90 ||
    longitude < -180 ||
    longitude > 180 ||
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
      "school_settings?select=id&order=id.asc&limit=1",
      {
        method: "GET"
      }
    );

  let rows;

  if (
    Array.isArray(existing) &&
    existing.length
  ) {

    rows =
      await supabaseRequest(
        `school_settings?id=eq.${existing[0].id}`,
        {
          method: "PATCH",
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

    rows =
      await supabaseRequest(
        "school_settings",
        {
          method: "POST",
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
      "GPS settings updated successfully.",
    settings:
      Array.isArray(rows)
        ? rows[0]
        : rows
  });

} catch (error) {

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
  });

}

}
);

/* =========================================================
GET TODAY ATTENDANCE - TEACHER
========================================================= */

app.get(
"/api/attendance/today",
authenticate,
requireTeacher,
async (req, res) => {

try {

  const date =
    getKenyaDate();

  const rows =
    await supabaseRequest(
      `attendance?select=*&staff_id=eq.${req.user.id}&attendance_date=eq.${date}&limit=1`,
      {
        method: "GET"
      }
    );

  res.json({
    success: true,
    attendance:
      rows?.[0] || null
  });

} catch (error) {

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
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
requireTeacher,
async (req, res) => {

try {

  const latitude =
    Number(req.body?.latitude);

  const longitude =
    Number(req.body?.longitude);

  const accuracy =
    Number(req.body?.accuracy);

  if (
    !isValidGPS(
      latitude,
      longitude,
      accuracy
    )
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Valid GPS coordinates and accuracy are required."
    });

  }

  if (accuracy > 500) {

    return res.status(400).json({
      success: false,
      message:
        "GPS accuracy is too low. Please move to an open area and try again."
    });

  }

  const settingsRows =
    await supabaseRequest(
      "school_settings?select=latitude,longitude,radius&order=id.asc&limit=1",
      {
        method: "GET"
      }
    );

  if (
    !settingsRows ||
    !settingsRows.length
  ) {

    return res.status(500).json({
      success: false,
      message:
        "School GPS settings have not been configured."
    });

  }

  const settings =
    settingsRows[0];

  const distance =
    haversineDistance(
      latitude,
      longitude,
      Number(settings.latitude),
      Number(settings.longitude)
    );

  const radius =
    Number(settings.radius) ||
    DEFAULT_RADIUS;

  if (distance > radius) {

    return res.status(403).json({
      success: false,
      message:
        `You are outside the school attendance area. Distance: ${Math.round(distance)} metres. Allowed: ${Math.round(radius)} metres.`,
      distance: Math.round(distance),
      radius
    });

  }

  const date =
    getKenyaDate();

  const existing =
    await supabaseRequest(
      `attendance?select=id,clock_in,clock_out&staff_id=eq.${req.user.id}&attendance_date=eq.${date}&limit=1`,
      {
        method: "GET"
      }
    );

  if (
    Array.isArray(existing) &&
    existing.length
  ) {

    return res.status(409).json({
      success: false,
      message:
        "You have already clocked in today."
    });

  }

  const now =
    new Date().toISOString();

  const status =
    getKenyaHour() >= 8
      ? "Late"
      : "Present";

  const rows =
    await supabaseRequest(
      "attendance",
      {
        method: "POST",
        body: JSON.stringify({
          staff_id:
            req.user.id,
          attendance_date:
            date,
          clock_in:
            now,
          status,
          gps_verified:
            true,
          clock_in_lat:
            latitude,
          clock_in_lon:
            longitude,
          clock_in_accuracy:
            accuracy,
          clock_in_distance:
            distance
        })
      }
    );

  res.json({
    success: true,
    message:
      "Clock-in recorded successfully.",
    attendance:
      Array.isArray(rows)
        ? rows[0]
        : rows
  });

} catch (error) {

  console.error(
    "Clock-in error:",
    error
  );

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
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
requireTeacher,
async (req, res) => {

try {

  const latitude =
    Number(req.body?.latitude);

  const longitude =
    Number(req.body?.longitude);

  const accuracy =
    Number(req.body?.accuracy);

  if (
    !isValidGPS(
      latitude,
      longitude,
      accuracy
    )
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Valid GPS coordinates and accuracy are required."
    });

  }

  if (accuracy > 500) {

    return res.status(400).json({
      success: false,
      message:
        "GPS accuracy is too low. Please try again."
    });

  }

  const settingsRows =
    await supabaseRequest(
      "school_settings?select=latitude,longitude,radius&order=id.asc&limit=1",
      {
        method: "GET"
      }
    );

  if (
    !settingsRows ||
    !settingsRows.length
  ) {

    return res.status(500).json({
      success: false,
      message:
        "School GPS settings have not been configured."
    });

  }

  const settings =
    settingsRows[0];

  const distance =
    haversineDistance(
      latitude,
      longitude,
      Number(settings.latitude),
      Number(settings.longitude)
    );

  const radius =
    Number(settings.radius) ||
    DEFAULT_RADIUS;

  if (distance > radius) {

    return res.status(403).json({
      success: false,
      message:
        `You are outside the school attendance area. Distance: ${Math.round(distance)} metres.`,
      distance:
        Math.round(distance),
      radius
    });

  }

  const date =
    getKenyaDate();

  const existing =
    await supabaseRequest(
      `attendance?select=*&staff_id=eq.${req.user.id}&attendance_date=eq.${date}&limit=1`,
      {
        method: "GET"
      }
    );

  if (
    !Array.isArray(existing) ||
    !existing.length
  ) {

    return res.status(400).json({
      success: false,
      message:
        "You must clock in before clocking out."
    });

  }

  const attendance =
    existing[0];

  if (attendance.clock_out) {

    return res.status(409).json({
      success: false,
      message:
        "You have already clocked out today."
    });

  }

  const now =
    new Date().toISOString();

  const rows =
    await supabaseRequest(
      `attendance?id=eq.${attendance.id}`,
      {
        method: "PATCH",
        body: JSON.stringify({
          clock_out:
            now,
          clock_out_lat:
            latitude,
          clock_out_lon:
            longitude,
          clock_out_accuracy:
            accuracy,
          clock_out_distance:
            distance
        })
      }
    );

  res.json({
    success: true,
    message:
      "Clock-out recorded successfully.",
    attendance:
      Array.isArray(rows)
        ? rows[0]
        : rows
  });

} catch (error) {

  console.error(
    "Clock-out error:",
    error
  );

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
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
requireTeacher,
async (req, res) => {

try {

  const rows =
    await supabaseRequest(
      `attendance?select=*&staff_id=eq.${req.user.id}&order=attendance_date.desc`,
      {
        method: "GET"
      }
    );

  res.json({
    success: true,
    attendance:
      rows || []
  });

} catch (error) {

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
  });

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

  const rows =
    await supabaseRequest(
      "staff?select=id,username,full_name,email,phone,role,active,created_at&order=full_name.asc",
      {
        method: "GET"
      }
    );

  res.json({
    success: true,
    staff:
      rows || []
  });

} catch (error) {

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
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

  const {
    full_name,
    email,
    phone,
    password,
    role
  } = req.body || {};

  /* -----------------------------------------------
     VALIDATION
  ------------------------------------------------ */

  if (
    typeof full_name !== "string" ||
    !full_name.trim()
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Teacher's full name is required."
    });

  }

  if (
    typeof email !== "string" ||
    !email.trim()
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Teacher's email address is required."
    });

  }

  if (
    typeof phone !== "string" ||
    !phone.trim()
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Teacher's contact number is required."
    });

  }

  if (
    typeof password !== "string" ||
    password.length < 8
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Password must contain at least 8 characters."
    });

  }

  const cleanName =
    full_name.trim();

  const cleanEmail =
    email.trim().toLowerCase();

  const cleanPhone =
    phone.trim();

  /*
    For the internal username we create a safe
    unique identifier based on the teacher's name.

    The portal displays the actual full name to the
    teacher and administrator.
  */

  const baseUsername =
    cleanName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, ".")
      .replace(/^\.|\.$/g, "")
      .slice(0, 40) ||
    "teacher";

  let username =
    baseUsername;

  let suffix = 1;

  while (true) {

    const existing =
      await supabaseRequest(
        `staff?select=id&username=eq.${encodeURIComponent(username)}&limit=1`,
        {
          method: "GET"
        }
      );

    if (
      !Array.isArray(existing) ||
      existing.length === 0
    ) {
      break;
    }

    suffix++;

    username =
      `${baseUsername}.${suffix}`;

  }

  /* -----------------------------------------------
     EMAIL DUPLICATE CHECK
  ------------------------------------------------ */

  const emailRows =
    await supabaseRequest(
      `staff?select=id&email=ilike.${encodeURIComponent(cleanEmail)}&limit=1`,
      {
        method: "GET"
      }
    );

  if (
    Array.isArray(emailRows) &&
    emailRows.length
  ) {

    return res.status(409).json({
      success: false,
      message:
        "A staff account already uses this email address."
    });

  }

  /* -----------------------------------------------
     PASSWORD HASH
  ------------------------------------------------ */

  const passwordHash =
    await bcrypt.hash(
      password,
      12
    );

  /* -----------------------------------------------
     ROLE
     Registration from admin page defaults to teacher.
  ------------------------------------------------ */

  const cleanRole =
    role === "admin"
      ? "admin"
      : "teacher";

  /* -----------------------------------------------
     CREATE ACCOUNT
  ------------------------------------------------ */

  const rows =
    await supabaseRequest(
      "staff",
      {
        method: "POST",
        body: JSON.stringify({
          username,
          password_hash:
            passwordHash,
          full_name:
            cleanName,
          email:
            cleanEmail,
          phone:
            cleanPhone,
          role:
            cleanRole,
          active:
            true
        })
      }
    );

  const created =
    Array.isArray(rows)
      ? rows[0]
      : rows;

  res.status(201).json({
    success: true,
    message:
      "Teacher registered successfully.",
    staff: {
      id:
        created?.id,
      username:
        created?.username ||
        username,
      full_name:
        created?.full_name ||
        cleanName,
      email:
        created?.email ||
        cleanEmail,
      phone:
        created?.phone ||
        cleanPhone,
      role:
        created?.role ||
        cleanRole,
      active:
        created?.active ??
        true,
      created_at:
        created?.created_at
    }
  });

} catch (error) {

  console.error(
    "Staff registration error:",
    error
  );

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message ||
      "Unable to register teacher."
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

  const id =
    Number(req.params.id);

  const active =
    Boolean(req.body?.active);

  if (
    !Number.isInteger(id) ||
    id <= 0
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Invalid staff ID."
    });

  }

  const rows =
    await supabaseRequest(
      `staff?id=eq.${id}`,
      {
        method: "PATCH",
        body: JSON.stringify({
          active
        })
      }
    );

  res.json({
    success: true,
    message:
      active
        ? "Staff account activated."
        : "Staff account deactivated.",
    staff:
      Array.isArray(rows)
        ? rows[0]
        : rows
  });

} catch (error) {

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
  });

}

}
);

/* =========================================================
ADMIN - STAFF PROFILE
========================================================= */

app.get(
"/api/admin/staff/:id",
authenticate,
requireAdmin,
async (req, res) => {

try {

  const id =
    Number(req.params.id);

  if (
    !Number.isInteger(id) ||
    id <= 0
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Invalid staff ID."
    });

  }

  const staffRows =
    await supabaseRequest(
      `staff?select=id,username,full_name,email,phone,role,active,created_at&id=eq.${id}&limit=1`,
      {
        method: "GET"
      }
    );

  if (
    !staffRows ||
    !staffRows.length
  ) {

    return res.status(404).json({
      success: false,
      message:
        "Staff member not found."
    });

  }

  const attendanceRows =
    await supabaseRequest(
      `attendance?select=*&staff_id=eq.${id}&order=attendance_date.desc`,
      {
        method: "GET"
      }
    );

  res.json({
    success: true,
    staff:
      staffRows[0],
    attendance:
      attendanceRows || []
  });

} catch (error) {

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
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

  const id =
    Number(req.params.id);

  const password =
    req.body?.password;

  if (
    !Number.isInteger(id) ||
    id <= 0
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Invalid staff ID."
    });

  }

  if (
    typeof password !== "string" ||
    password.length < 8
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Password must contain at least 8 characters."
    });

  }

  const passwordHash =
    await bcrypt.hash(
      password,
      12
    );

  await supabaseRequest(
    `staff?id=eq.${id}`,
    {
      method: "PATCH",
      body: JSON.stringify({
        password_hash:
          passwordHash
      })
    }
  );

  res.json({
    success: true,
    message:
      "Password reset successfully."
  });

} catch (error) {

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
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

  const date =
    getKenyaDate();

  const staffRows =
    await supabaseRequest(
      "staff?select=id,username,full_name,email,phone,role,active&role=eq.teacher&order=full_name.asc",
      {
        method: "GET"
      }
    );

  const attendanceRows =
    await supabaseRequest(
      `attendance?select=*&attendance_date=eq.${date}`,
      {
        method: "GET"
      }
    );

  const attendanceMap =
    new Map(
      (attendanceRows || [])
        .map(row =>
          [
            Number(row.staff_id),
            row
          ]
        )
    );

  const result =
    (staffRows || []).map(
      staff => {

        const attendance =
          attendanceMap.get(
            Number(staff.id)
          ) || null;

        return {
          ...staff,
          ...(attendance || {}),
          staff_id:
            staff.id
        };

      }
    );

  res.json({
    success: true,
    date,
    attendance:
      result
  });

} catch (error) {

  console.error(
    "Admin attendance error:",
    error
  );

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
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

  const date =
    getKenyaDate();

  const staffRows =
    await supabaseRequest(
      "staff?select=id,full_name,email,phone&role=eq.teacher",
      {
        method: "GET"
      }
    );

  const attendanceRows =
    await supabaseRequest(
      `attendance?select=*&attendance_date=eq.${date}&order=created_at.desc`,
      {
        method: "GET"
      }
    );

  const staffMap =
    new Map(
      (staffRows || [])
        .map(
          staff =>
            [
              Number(staff.id),
              staff
            ]
        )
    );

  const result = [];

  for (
    const row of attendanceRows || []
  ) {

    const staff =
      staffMap.get(
        Number(row.staff_id)
      );

    if (
      row.clock_in_lat !== null &&
      row.clock_in_lat !== undefined
    ) {

      result.push({
        id:
          row.id,
        staff_id:
          row.staff_id,
        full_name:
          staff?.full_name ||
          "Unknown",
        email:
          staff?.email ||
          null,
        phone:
          staff?.phone ||
          null,
        event:
          "Clock In",
        latitude:
          row.clock_in_lat,
        longitude:
          row.clock_in_lon,
        accuracy:
          row.clock_in_accuracy,
        distance:
          row.clock_in_distance,
        gps_verified:
          row.gps_verified,
        time:
          row.clock_in
      });

    }

    if (
      row.clock_out_lat !== null &&
      row.clock_out_lat !== undefined
    ) {

      result.push({
        id:
          `${row.id}-out`,
        staff_id:
          row.staff_id,
        full_name:
          staff?.full_name ||
          "Unknown",
        email:
          staff?.email ||
          null,
        phone:
          staff?.phone ||
          null,
        event:
          "Clock Out",
        latitude:
          row.clock_out_lat,
        longitude:
          row.clock_out_lon,
        accuracy:
          row.clock_out_accuracy,
        distance:
          row.clock_out_distance,
        gps_verified:
          true,
        time:
          row.clock_out
      });

    }

  }

  res.json({
    success: true,
    date,
    gps:
      result
  });

} catch (error) {

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
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

  const date =
    getKenyaDate();

  const staffRows =
    await supabaseRequest(
      "staff?select=id&role=eq.teacher&active=eq.true",
      {
        method: "GET"
      }
    );

  const attendanceRows =
    await supabaseRequest(
      `attendance?select=status,clock_in,clock_out&attendance_date=eq.${date}`,
      {
        method: "GET"
      }
    );

  const totalStaff =
    staffRows?.length || 0;

  let present = 0;
  let late = 0;
  let clockedOut = 0;

  for (
    const row of attendanceRows || []
  ) {

    if (row.clock_in) {
      present++;
    }

    if (row.status === "Late") {
      late++;
    }

    if (row.clock_out) {
      clockedOut++;
    }

  }

  res.json({
    success: true,
    date,
    summary: {
      totalStaff,
      totalTeachers:
        totalStaff,
      present,
      presentToday:
        present,
      late,
      lateToday:
        late,
      clockedOut,
      clockedOutToday:
        clockedOut
    }
  });

} catch (error) {

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
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

  const id =
    Number(req.params.id);

  if (
    !Number.isInteger(id) ||
    id <= 0
  ) {

    return res.status(400).json({
      success: false,
      message:
        "Invalid attendance ID."
    });

  }

  const rows =
    await supabaseRequest(
      `attendance?select=*&id=eq.${id}&limit=1`,
      {
        method: "GET"
      }
    );

  if (
    !rows ||
    !rows.length
  ) {

    return res.status(404).json({
      success: false,
      message:
        "Attendance record not found."
    });

  }

  res.json({
    success: true,
    attendance:
      rows[0]
  });

} catch (error) {

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
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

  const staffId =
    Number(req.query.staff_id);

  if (
    !Number.isInteger(staffId) ||
    staffId <= 0
  ) {

    return res.status(400).json({
      success: false,
      message:
        "A valid staff_id is required."
    });

  }

  const from =
    req.query.from ||
    null;

  const to =
    req.query.to ||
    null;

  const staffRows =
    await supabaseRequest(
      `staff?select=id,username,full_name,email,phone,role,active,created_at&id=eq.${staffId}&limit=1`,
      {
        method: "GET"
      }
    );

  if (
    !staffRows ||
    !staffRows.length
  ) {

    return res.status(404).json({
      success: false,
      message:
        "Teacher not found."
    });

  }

  let attendancePath =
    `attendance?select=*&staff_id=eq.${staffId}&order=attendance_date.asc`;

  if (from) {
    attendancePath +=
      `&attendance_date=gte.${encodeURIComponent(from)}`;
  }

  if (to) {
    attendancePath +=
      `&attendance_date=lte.${encodeURIComponent(to)}`;
  }

  const attendanceRows =
    await supabaseRequest(
      attendancePath,
      {
        method: "GET"
      }
    );

  const rows =
    attendanceRows || [];

  let daysPresent = 0;
  let lateDays = 0;
  let missingClockOut = 0;

  for (
    const row of rows
  ) {

    if (row.clock_in) {
      daysPresent++;
    }

    if (
      row.status === "Late"
    ) {
      lateDays++;
    }

    if (
      row.clock_in &&
      !row.clock_out
    ) {
      missingClockOut++;
    }

  }

  const attendancePercentage =
    rows.length
      ? Number(
          (
            daysPresent /
            rows.length *
            100
          ).toFixed(1)
        )
      : 0;

  res.json({
    success: true,

    report: {

      staff:
        staffRows[0],

      from,
      to,

      attendance:
        rows,

      days_present:
        daysPresent,

      late_days:
        lateDays,

      missing_clock_out:
        missingClockOut,

      attendance_percentage:
        attendancePercentage

    }

  });

} catch (error) {

  console.error(
    "Report error:",
    error
  );

  res.status(
    error.status || 500
  ).json({
    success: false,
    message:
      error.message
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

  const message =
    String(
      req.body?.message || ""
    ).trim();

  if (!message) {

    return res.status(400).json({
      success: false,
      message:
        "Please enter a question."
    });

  }

  /*
    AI will be securely connected here.

    The browser will NEVER receive:
    - SUPABASE_SERVICE_ROLE_KEY
    - JWT_SECRET
    - AI provider secret

    The next development step will connect
    this endpoint to the selected AI service.
  */

  res.json({
    success: true,
    reply:
      "The S.C.A.G.S.S AI Assistant interface is ready. Secure AI analysis will be connected in the next step."
  });

} catch (error) {

  res.status(500).json({
    success: false,
    message:
      "AI Assistant error."
  });

}

}
);

/* =========================================================
UNKNOWN API ROUTE
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
GLOBAL ERROR HANDLER
========================================================= */

app.use(
(error, req, res, next) => {

console.error(
  "Server error:",
  error
);

res.status(
  error.status || 500
).json({
  success: false,
  message:
    error.message ||
    "Internal server error."
});

}
);

/* =========================================================
VERCEL EXPORT
========================================================= */

module.exports = app;
