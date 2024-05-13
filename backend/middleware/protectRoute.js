import jwt from "jsonwebtoken"; // Importing JWT for token verification
import User from "../models/user.model.js"; // Importing User model

// Middleware to protect routes by verifying JWT token
const protectRoute = async (req, res, next) => {
	try {
		const token = req.cookies.jwt; // Extracting JWT token from cookies

		// If no token is provided, return 401 Unauthorized
		if (!token) {
			return res.status(401).json({ error: "Unauthorized - No Token Provided" });
		}

		// Verifying the token using JWT library and the secret key
		const decoded = jwt.verify(token, process.env.JWT_SECRET);

		// If token verification fails, return 401 Unauthorized
		if (!decoded) {
			return res.status(401).json({ error: "Unauthorized - Invalid Token" });
		}

		// Finding user based on the decoded user ID from the token and excluding the password field
		const user = await User.findById(decoded.userId).select("-password");

		// If user is not found, return 404 Not Found
		if (!user) {
			return res.status(404).json({ error: "User not found" });
		}

		// Attach user object to the request for further processing
		req.user = user;

		next(); // Continue to the next middleware
	} catch (error) {
		// If any error occurs, log the error message and return 500 Internal Server Error
		console.log("Error in protectRoute middleware: ", error.message);
		res.status(500).json({ error: "Internal server error" });
	}
};

export default protectRoute; // Exporting the middleware for use in other files
