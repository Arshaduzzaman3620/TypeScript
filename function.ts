import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

// Production-level login function
interface LoginRequest {
  username: string;
  password: string;
}

interface LoginResponse {
  success: boolean;
  token?: string;
  message: string;
}

const users: { [username: string]: { passwordHash: string; role: string } } = {
  admin: {
    passwordHash: "$2b$10$.H5PgAgweAL0/7C4kFk38.2MfY5kanR8ApPSRvs7I5QtbKrSHtbDu", // Pre-hashed password for 'password123'
    role: "admin",
  },
};

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET environment variable is required");
}

export async function login(request: LoginRequest): Promise<LoginResponse> {
  try {
    // Input validation
    if (!request.username || !request.password) {
      return {
        success: false,
        message: "Username and password are required",
      };
    }

    if (request.username.length < 3 || request.password.length < 6) {
      return {
        success: false,
        message:
          "Username must be at least 3 characters and password at least 6 characters",
      };
    }

    // Check if user exists
    const user = users[request.username];
    if (!user) {
      return {
        success: false,
        message: "Invalid username or password",
      };
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(
      request.password,
      user.passwordHash
    );
    if (!isPasswordValid) {
      return {
        success: false,
        message: "Invalid username or password",
      };
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        username: request.username,
        role: user.role,
        iat: Math.floor(Date.now() / 1000),
      },
      JWT_SECRET,
      { expiresIn: "1h" } // Token expires in 1 hour
    );

    return {
      success: true,
      token,
      message: "Login successful",
    };
  } catch (error) {
    console.error("Login error:", error);
    return {
      success: false,
      message: "Internal server error",
    };
  }
}

// Utility function to hash a password (for creating users)
export async function hashPassword(password: string): Promise<string> {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}

// Example usage (for testing)
async function example() {
  // Hash a password for storage
  const hashed = await hashPassword("password123");
  console.log("Hashed password:", hashed);

  // Login attempt
  const result = await login({ username: "admin", password: "password123" });
  console.log("Login result:", result);
}

// Uncomment to run example
// example();
