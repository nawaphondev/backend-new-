const jwt = require("jsonwebtoken");

const authorize = () => {
  return (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(403).json({ error: "No token provided" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) return res.status(403).json({ error: "Invalid or expired token" });

      req.user = decoded; // Attach decoded token payload to req.user
      next();
    });
  };
};

module.exports = authorize;
