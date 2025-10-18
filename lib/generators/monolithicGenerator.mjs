import { BaseGenerator } from './baseGenerator.mjs';
import fs from 'fs-extra';
import path from 'path';

export class MonolithicGenerator extends BaseGenerator {
  async generate() {
    await this.ensureDirectory(this.projectPath);

    // Create directory structure
    const dirs = [
      "src/controllers",
      "src/models",
      "src/routes",
      "src/middlewares",
      "src/services",
      "src/utils",
      "src/config",
      "src/validators",
      "uploads",
      "tests",
    ];

    // Add prisma directory if Prisma is selected
    if (this.config.database === "prisma") {
      dirs.push("prisma");
    }

    for (const dir of dirs) {
      await this.ensureDirectory(path.join(this.projectPath, dir));
    }

    // Generate files
    await this.generatePackageJson();
    await this.generateServerFile();
    await this.generateEnvFile();
    await this.generateGitignore();
    await this.generateConfigFiles();
    await this.generateBasicStructure();

    // Generate feature-specific files
    if (this.config.features.includes("fileUpload")) {
      await this.generateFileUploadSetup();
    }

    if (this.config.features.includes("email")) {
      await this.generateEmailSetup();
    }

    if (this.config.features.includes("docs")) {
      await this.generateAPIDocs();
    }

    if (this.config.features.includes("docker")) {
      await this.generateDockerfile();
    }

    if (this.config.features.includes("rateLimit")) {
      await this.generateRateLimiting();
    }

    if (this.config.features.includes("validation")) {
      await this.generateValidation();
    }
  }

  async generatePackageJson() {
    const packageJson = this.getPackageJson();
    await fs.writeJson(
      path.join(this.projectPath, "package.json"),
      packageJson,
      { spaces: 2 }
    );
  }

  async generateServerFile() {
    const isCJS = this.config.moduleType === "cjs";

    let serverImports = "";
    let serverSetup = "";

    if (isCJS) {
      serverImports = `const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const dotenv = require('dotenv');
`;
    } else {
      serverImports = `import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';
`;
    }

    // Add database connection if selected
    if (this.config.database !== "none") {
      if (isCJS) {
        serverImports += `const {connectDB} = require('./src/config/database.js');\n`;
      } else {
        serverImports += `import connectDB from './src/config/database.js';\n`;
      }
      serverSetup += `
// Database connection
connectDB();
`;
    }

    // Add rate limiting if selected
    if (this.config.features.includes("rateLimit")) {
      if (isCJS) {
        serverImports += `const rateLimit = require('./src/middlewares/rateLimit.js');\n`;
      } else {
        serverImports += `import rateLimit from './src/middlewares/rateLimit.js';\n`;
      }
    }

    // Add Swagger if selected
    if (this.config.features.includes("docs")) {
      if (isCJS) {
        serverImports += `const swaggerUi = require('swagger-ui-express');
const swaggerSpec = require('./src/config/swagger.js');\n`;
      } else {
        serverImports += `import swaggerUi from 'swagger-ui-express';
import swaggerSpec from './src/config/swagger.js';\n`;
      }
    }

    // Import routes
    if (isCJS) {
      serverImports += `
// Import routes
const authRoutes = require('./src/routes/authRoutes.js');
const userRoutes = require('./src/routes/userRoutes.js');
`;

      if (this.config.features.includes("fileUpload")) {
        serverImports += `const uploadRoutes = require('./src/routes/uploadRoutes.js');\n`;
      }

      if (this.config.features.includes("email")) {
        serverImports += `const emailRoutes = require('./src/routes/emailRoutes.js');\n`;
      }
    } else {
      serverImports += `
// Import routes
import authRoutes from './src/routes/authRoutes.js';
import userRoutes from './src/routes/userRoutes.js';
`;

      if (this.config.features.includes("fileUpload")) {
        serverImports += `import uploadRoutes from './src/routes/uploadRoutes.js';\n`;
      }

      if (this.config.features.includes("email")) {
        serverImports += `import emailRoutes from './src/routes/emailRoutes.js';\n`;
      }
    }

    const serverTemplate = `${serverImports}

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));${
      this.config.features.includes("rateLimit")
        ? `
app.use(rateLimit);`
        : ""
    }

// Static files
app.use('/uploads', express.static('uploads'));${
      this.config.features.includes("docs")
        ? `
// API Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));`
        : ""
    }
${serverSetup}
// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);${
      this.config.features.includes("fileUpload")
        ? `
app.use('/api/upload', uploadRoutes);`
        : ""
    }${
      this.config.features.includes("email")
        ? `
app.use('/api/email', emailRoutes);`
        : ""
    }

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found' 
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error(error.stack);
  res.status(500).json({ 
    error: 'Something went wrong!' 
  });
});

app.listen(PORT, () => {
  console.log(\`🚀 Server running on port \${PORT}\`);
  console.log(\`📊 Environment: \${process.env.NODE_ENV}\`);${
    this.config.features.includes("docs")
      ? `
  console.log(\`📚 API Docs: http://localhost:\${PORT}/api-docs\`);`
      : ""
  }
});
${isCJS ? "module.exports = app;" : "export default app;"}
`;

    const fileName =
      this.config.moduleType === "mjs" ? "server.mjs" : "server.js";
    await fs.writeFile(path.join(this.projectPath, fileName), serverTemplate);
  }

  async generateEnvFile() {
    const envContent = this.getEnvContent();
    await fs.writeFile(path.join(this.projectPath, ".env"), envContent);
    await fs.writeFile(path.join(this.projectPath, ".env.example"), envContent);
  }

  async generateGitignore() {
    const gitignore = `node_modules/
.env
.DS_Store
uploads/*
!uploads/.gitkeep
npm-debug.log*
yarn-debug.log*
yarn-error.log*
.vscode/
.idea/
coverage/
*.log
`;
    await fs.writeFile(path.join(this.projectPath, ".gitignore"), gitignore);
    await fs.writeFile(path.join(this.projectPath, "uploads/.gitkeep"), "");
  }

  async generateConfigFiles() {
    const ext = "js";

    // Database config
    if (this.config.database !== "none") {
      const dbConfig = this.getDatabaseConfig();
      await fs.writeFile(
        path.join(this.projectPath, `src/config/database.${ext}`),
        dbConfig
      );
    }

    // Auth middleware
    if (this.config.features.includes("auth")) {
      const authMiddleware = this.getAuthMiddleware();
      await fs.writeFile(
        path.join(this.projectPath, `src/middlewares/auth.${ext}`),
        authMiddleware
      );
    }

    // Swagger config
    if (this.config.features.includes("docs")) {
      const swaggerConfig = this.getSwaggerConfig();
      await fs.writeFile(
        path.join(this.projectPath, `src/config/swagger.${ext}`),
        swaggerConfig
      );
    }
  }

  getAuthMiddleware() {
    const isCJS = this.config.moduleType === "cjs";

    if (isCJS) {
      return `const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

const optionalAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (!err) {
        req.user = user;
      }
    });
  }
  next();
};

module.exports = { authenticateToken, optionalAuth };
`;
    } else {
      return `import jwt from 'jsonwebtoken';

export const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

export const optionalAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (!err) {
        req.user = user;
      }
    });
  }
  next();
};
`;
    }
  }

  getSwaggerConfig() {
    const isCJS = this.config.moduleType === "cjs";

    if (isCJS) {
      return `const swaggerJSDoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: '${this.config.projectName} API',
      version: '1.0.0',
      description: 'API documentation for ${this.config.projectName}',
    },
    servers: [
      {
        url: 'http://localhost:${process.env.PORT || 3000}',
        description: 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
  },
  apis: ['./src/routes/*.js'],
};

const swaggerSpec = swaggerJSDoc(options);

module.exports = swaggerSpec;
`;
    } else {
      return `import swaggerJSDoc from 'swagger-jsdoc';

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: '${this.config.projectName} API',
      version: '1.0.0',
      description: 'API documentation for ${this.config.projectName}',
    },
    servers: [
      {
        url: 'http://localhost:${process.env.PORT || 3000}',
        description: 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
  },
  apis: ['./src/routes/*.js'],
};

const swaggerSpec = swaggerJSDoc(options);

export default swaggerSpec;
`;
    }
  }

  async generateBasicStructure() {
    const ext = "js";

    // Generate Prisma schema first if Prisma is selected
    if (this.config.database === "prisma") {
      await this.generatePrismaSchema();
    }

    // Generate models based on database selection
    await this.generateModels(ext);

    // Generate controllers and routes
    await this.generateUserController(ext);
    await this.generateUserRoutes(ext);

    // Auth Routes and Controller
    if (this.config.features.includes("auth")) {
      await this.generateAuthSetup(ext);
    }
  }

  async generatePrismaSchema() {
    if (this.config.database !== "prisma") return;

    const prismaSchema = `// This is your Prisma schema file,
// learn more about it in the docs: https://pris.ly/d/prisma-schema

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "mysql"
  url      = env("DATABASE_URL")
}

model User {
  id        String   @id @default(cuid())
  name      String
  email     String   @unique
  password  String
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  files     File[]

  @@map("users")
}

model File {
  id           String   @id @default(cuid())
  filename     String
  originalName String
  mimetype     String
  size         Int
  path         String
  userId       String?
  user         User?    @relation(fields: [userId], references: [id])
  createdAt    DateTime @default(now())
  updatedAt    DateTime @updatedAt

  @@map("files")
}
`;

    await fs.writeFile(
      path.join(this.projectPath, "prisma/schema.prisma"),
      prismaSchema
    );
  }

  async generateModels(ext) {
    if (this.config.database === "none") return;

    // User Model
    const userModel = this.getUserModel();
    if (userModel) {
      await fs.writeFile(
        path.join(this.projectPath, `src/models/User.${ext}`),
        userModel
      );
    }

    // Additional models for file upload if selected
    if (
      this.config.features.includes("fileUpload") &&
      this.config.database !== "prisma"
    ) {
      const fileModel = this.getFileModel();
      if (fileModel) {
        await fs.writeFile(
          path.join(this.projectPath, `src/models/File.${ext}`),
          fileModel
        );
      }
    }
  }

  async generateUserController(ext) {
    const isCJS = this.config.moduleType === "cjs";

    let userController = `/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       properties:
 *         id:
 *           type: string
 *         name:
 *           type: string
 *         email:
 *           type: string
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 */

/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Get all users
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of users
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/User'
 */
`;

    if (isCJS) {
      userController += `const getUsers = async (req, res) => {
  try {
    // Implementation here
    const users = []; // Replace with actual database call
    res.json({ 
      success: true,
      data: users 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Get user by ID
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User data
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 */
const getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    // Implementation here
    const user = { id, name: 'John Doe', email: 'john@example.com' }; // Replace with actual database call
    res.json({ 
      success: true,
      data: user 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

module.exports = { getUsers, getUserById };
`;
    } else {
      userController += `export const getUsers = async (req, res) => {
  try {
    // Implementation here
    const users = []; // Replace with actual database call
    res.json({ 
      success: true,
      data: users 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * @swagger
 * /api/users/{id}:
 *   get:
 *     summary: Get user by ID
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User data
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 */
export const getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    // Implementation here
    const user = { id, name: 'John Doe', email: 'john@example.com' }; // Replace with actual database call
    res.json({ 
      success: true,
      data: user 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};
`;
    }

    await fs.writeFile(
      path.join(this.projectPath, `src/controllers/userController.${ext}`),
      userController
    );
  }

  async generateUserRoutes(ext) {
    const isCJS = this.config.moduleType === "cjs";

    let userRoutes = "";

    if (isCJS) {
      userRoutes = `const express = require('express');
const { getUsers, getUserById } = require('../controllers/userController.js');
const { authenticateToken } = require('../middlewares/auth.js');

const router = express.Router();

router.get('/', authenticateToken, getUsers);
router.get('/:id', authenticateToken, getUserById);

module.exports = router;
`;
    } else {
      userRoutes = `import express from 'express';
import { getUsers, getUserById } from '../controllers/userController.js';
import { authenticateToken } from '../middlewares/auth.js';

const router = express.Router();

router.get('/', authenticateToken, getUsers);
router.get('/:id', authenticateToken, getUserById);

export default router;
`;
    }

    await fs.writeFile(
      path.join(this.projectPath, `src/routes/userRoutes.${ext}`),
      userRoutes
    );
  }

  async generateAuthSetup(ext) {
    const isCJS = this.config.moduleType === "cjs";

    // Auth Routes
    let authRoutes = `/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 */

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 */

/**
 * @swagger
 * /api/auth/profile:
 *   get:
 *     summary: Get user profile
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile data
 */
`;

    if (isCJS) {
      authRoutes += `const express = require('express');
const { register, login, getProfile } = require('../controllers/authController.js');
const { authenticateToken } = require('../middlewares/auth.js');
const { validateRegister, validateLogin } = require('../middlewares/validation.js');

const router = express.Router();

router.post('/register', validateRegister, register);
router.post('/login', validateLogin, login);
router.get('/profile', authenticateToken, getProfile);

module.exports = router;
`;
    } else {
      authRoutes += `import express from 'express';
import { register, login, getProfile } from '../controllers/authController.js';
import { authenticateToken } from '../middlewares/auth.js';
import { validateRegister, validateLogin } from '../middlewares/validation.js';

const router = express.Router();

router.post('/register', validateRegister, register);
router.post('/login', validateLogin, login);
router.get('/profile', authenticateToken, getProfile);

export default router;
`;
    }

    await fs.writeFile(
      path.join(this.projectPath, `src/routes/authRoutes.${ext}`),
      authRoutes
    );

    // Auth Controller
    const authController = this.getAuthController();
    await fs.writeFile(
      path.join(this.projectPath, `src/controllers/authController.${ext}`),
      authController
    );
  }

  getAuthController() {
    const isCJS = this.config.moduleType === "cjs";

    if (isCJS) {
      return `const jwt = require('jsonwebtoken');
const  User  = require('../models/User.js');

const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user exists
    const existingUser = await User.findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        error: 'User already exists' 
      });
    }

    // Create user
    const user = await User.createUser({ name, email, password });

    // Generate token
    const token = jwt.sign(
      { userId: user.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findUserByEmail(email);
    if (!user) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    // Check password
    const isMatch = await User.comparePassword(user, password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

const getProfile = async (req, res) => {
  try {
    const user = await User.findUserById(req.user.userId);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found' 
      });
    }

    res.json({
      success: true,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

module.exports = { register, login, getProfile };
`;
    } else {
      return `import jwt from 'jsonwebtoken';
import  User  from '../models/User.js';

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user exists
    const existingUser = await User.findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        error: 'User already exists' 
      });
    }

    // Create user
    const user = await User.createUser({ name, email, password });

    // Generate token
    const token = jwt.sign(
      { userId: user.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findUserByEmail(email);
    if (!user) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    // Check password
    const isMatch = await User.comparePassword(user, password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

export const getProfile = async (req, res) => {
  try {
    const user = await User.findUserById(req.user.userId);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found' 
      });
    }

    res.json({
      success: true,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};
`;
    }
  }

  // ========== EMAIL SETUP ==========
  async generateEmailSetup() {
    const ext = "js";
    const isCJS = this.config.moduleType === "cjs";

    // Email Service
    const emailService = this.getEmailService();
    await fs.writeFile(
      path.join(this.projectPath, `src/services/emailService.${ext}`),
      emailService
    );

    // Email Controller
    const emailController = this.getEmailController();
    await fs.writeFile(
      path.join(this.projectPath, `src/controllers/emailController.${ext}`),
      emailController
    );

    // Email Routes
    const emailRoutes = this.getEmailRoutes();
    await fs.writeFile(
      path.join(this.projectPath, `src/routes/emailRoutes.${ext}`),
      emailRoutes
    );
  }

  getEmailService() {
    const isCJS = this.config.moduleType === "cjs";

    if (isCJS) {
      return `const nodemailer = require('nodemailer');

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }

  async sendEmail(to, subject, html, text = '') {
    try {
      const mailOptions = {
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to,
        subject,
        text,
        html,
      };

      const result = await this.transporter.sendMail(mailOptions);
      console.log('Email sent successfully:', result.messageId);
      return { success: true, messageId: result.messageId };
    } catch (error) {
      console.error('Error sending email:', error);
      throw new Error('Failed to send email');
    }
  }

  async sendWelcomeEmail(user) {
    const subject = 'Welcome to Our Platform!';
    const html = \`
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Welcome to Our Platform!</h2>
        <p>Hello \${user.name},</p>
        <p>Thank you for registering with us. We're excited to have you on board!</p>
        <p>Your account has been successfully created and you can now start using our services.</p>
        <p>If you have any questions, feel free to reach out to our support team.</p>
        <br>
        <p>Best regards,<br>The \${process.env.APP_NAME || 'App'} Team</p>
      </div>
    \`;

    return await this.sendEmail(user.email, subject, html);
  }

  async sendPasswordResetEmail(user, resetToken) {
    const resetUrl = \`\${process.env.CLIENT_URL}/reset-password?token=\${resetToken}\`;
    const subject = 'Password Reset Request';
    const html = \`
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Password Reset Request</h2>
        <p>Hello \${user.name},</p>
        <p>You requested to reset your password. Click the link below to reset it:</p>
        <p style="text-align: center; margin: 30px 0;">
          <a href="\${resetUrl}" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
        </p>
        <p><strong>This link will expire in 1 hour.</strong></p>
        <p>If you didn't request this, please ignore this email and your password will remain unchanged.</p>
        <br>
        <p>Best regards,<br>The \${process.env.APP_NAME || 'App'} Team</p>
      </div>
    \`;

    return await this.sendEmail(user.email, subject, html);
  }

  async sendNotificationEmail(user, title, message) {
    const subject = title;
    const html = \`
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">\${title}</h2>
        <p>Hello \${user.name},</p>
        <p>\${message}</p>
        <br>
        <p>Best regards,<br>The \${process.env.APP_NAME || 'App'} Team</p>
      </div>
    \`;

    return await this.sendEmail(user.email, subject, html);
  }
}

module.exports = new EmailService();
`;
    } else {
      return `import nodemailer from 'nodemailer';

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }

  async sendEmail(to, subject, html, text = '') {
    try {
      const mailOptions = {
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to,
        subject,
        text,
        html,
      };

      const result = await this.transporter.sendMail(mailOptions);
      console.log('Email sent successfully:', result.messageId);
      return { success: true, messageId: result.messageId };
    } catch (error) {
      console.error('Error sending email:', error);
      throw new Error('Failed to send email');
    }
  }

  async sendWelcomeEmail(user) {
    const subject = 'Welcome to Our Platform!';
    const html = \`
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Welcome to Our Platform!</h2>
        <p>Hello \${user.name},</p>
        <p>Thank you for registering with us. We're excited to have you on board!</p>
        <p>Your account has been successfully created and you can now start using our services.</p>
        <p>If you have any questions, feel free to reach out to our support team.</p>
        <br>
        <p>Best regards,<br>The \${process.env.APP_NAME || 'App'} Team</p>
      </div>
    \`;

    return await this.sendEmail(user.email, subject, html);
  }

  async sendPasswordResetEmail(user, resetToken) {
    const resetUrl = \`\${process.env.CLIENT_URL}/reset-password?token=\${resetToken}\`;
    const subject = 'Password Reset Request';
    const html = \`
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Password Reset Request</h2>
        <p>Hello \${user.name},</p>
        <p>You requested to reset your password. Click the link below to reset it:</p>
        <p style="text-align: center; margin: 30px 0;">
          <a href="\${resetUrl}" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
        </p>
        <p><strong>This link will expire in 1 hour.</strong></p>
        <p>If you didn't request this, please ignore this email and your password will remain unchanged.</p>
        <br>
        <p>Best regards,<br>The \${process.env.APP_NAME || 'App'} Team</p>
      </div>
    \`;

    return await this.sendEmail(user.email, subject, html);
  }

  async sendNotificationEmail(user, title, message) {
    const subject = title;
    const html = \`
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">\${title}</h2>
        <p>Hello \${user.name},</p>
        <p>\${message}</p>
        <br>
        <p>Best regards,<br>The \${process.env.APP_NAME || 'App'} Team</p>
      </div>
    \`;

    return await this.sendEmail(user.email, subject, html);
  }
}

export default new EmailService();
`;
    }
  }

  getEmailController() {
    const isCJS = this.config.moduleType === "cjs";

    if (isCJS) {
      return `const EmailService = require('../services/emailService.js');
const  User  = require('../models/User.js');
const crypto = require('crypto');

const sendTestEmail = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email is required'
      });
    }

    await EmailService.sendEmail(
      email,
      'Test Email from ${this.config.projectName}',
      \`
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Test Email</h2>
          <p>This is a test email from your <strong>${this.config.projectName}</strong> backend service.</p>
          <p>If you received this email, your email configuration is working correctly!</p>
          <br>
          <p>Best regards,<br>Your Backend Team</p>
        </div>
      \`,
      'Test Email: This is a test email from your backend service. If you received this, your email configuration is working correctly!'
    );

    res.json({
      success: true,
      message: 'Test email sent successfully'
    });
  } catch (error) {
    console.error('Error sending test email:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

const requestPasswordReset = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email is required'
      });
    }

    const user = await User.findUserByEmail(email);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found with this email address'
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    console.log('Password reset token (for development):', resetToken);

    await EmailService.sendPasswordResetEmail(user, resetToken);

    res.json({
      success: true,
      message: 'Password reset email sent successfully. Please check your inbox.'
    });
  } catch (error) {
    console.error('Error sending password reset email:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

const sendWelcomeEmail = async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: 'User ID is required'
      });
    }

    const user = await User.findUserById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    await EmailService.sendWelcomeEmail(user);

    res.json({
      success: true,
      message: 'Welcome email sent successfully'
    });
  } catch (error) {
    console.error('Error sending welcome email:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

const sendNotificationEmail = async (req, res) => {
  try {
    const { userId, title, message } = req.body;

    if (!userId || !title || !message) {
      return res.status(400).json({
        success: false,
        error: 'User ID, title, and message are required'
      });
    }

    const user = await User.findUserById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    await EmailService.sendNotificationEmail(user, title, message);

    res.json({
      success: true,
      message: 'Notification email sent successfully'
    });
  } catch (error) {
    console.error('Error sending notification email:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

module.exports = {
  sendTestEmail,
  requestPasswordReset,
  sendWelcomeEmail,
  sendNotificationEmail
};
`;
    } else {
      return `import EmailService from '../services/emailService.js';
import { User } from '../models/User.js';
import crypto from 'crypto';

export const sendTestEmail = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email is required'
      });
    }

    await EmailService.sendEmail(
      email,
      'Test Email from ${this.config.projectName}',
      \`
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Test Email</h2>
          <p>This is a test email from your <strong>${this.config.projectName}</strong> backend service.</p>
          <p>If you received this email, your email configuration is working correctly!</p>
          <br>
          <p>Best regards,<br>Your Backend Team</p>
        </div>
      \`,
      'Test Email: This is a test email from your backend service. If you received this, your email configuration is working correctly!'
    );

    res.json({
      success: true,
      message: 'Test email sent successfully'
    });
  } catch (error) {
    console.error('Error sending test email:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

export const requestPasswordReset = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email is required'
      });
    }

    const user = await User.findUserByEmail(email);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found with this email address'
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    console.log('Password reset token (for development):', resetToken);

    await EmailService.sendPasswordResetEmail(user, resetToken);

    res.json({
      success: true,
      message: 'Password reset email sent successfully. Please check your inbox.'
    });
  } catch (error) {
    console.error('Error sending password reset email:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

export const sendWelcomeEmail = async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: 'User ID is required'
      });
    }

    const user = await User.findUserById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    await EmailService.sendWelcomeEmail(user);

    res.json({
      success: true,
      message: 'Welcome email sent successfully'
    });
  } catch (error) {
    console.error('Error sending welcome email:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

export const sendNotificationEmail = async (req, res) => {
  try {
    const { userId, title, message } = req.body;

    if (!userId || !title || !message) {
      return res.status(400).json({
        success: false,
        error: 'User ID, title, and message are required'
      });
    }

    const user = await User.findUserById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    await EmailService.sendNotificationEmail(user, title, message);

    res.json({
      success: true,
      message: 'Notification email sent successfully'
    });
  } catch (error) {
    console.error('Error sending notification email:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};
`;
    }
  }

  getEmailRoutes() {
    const isCJS = this.config.moduleType === "cjs";

    if (isCJS) {
      return `const express = require('express');
const {
  sendTestEmail,
  requestPasswordReset,
  sendWelcomeEmail,
  sendNotificationEmail
} = require('../controllers/emailController.js');
const { authenticateToken } = require('../middlewares/auth.js');
const { validateEmail } = require('../middlewares/validation.js');

const router = express.Router();

router.post('/test', authenticateToken, sendTestEmail);
router.post('/password-reset', validateEmail, requestPasswordReset);
router.post('/welcome', authenticateToken, sendWelcomeEmail);
router.post('/notification', authenticateToken, sendNotificationEmail);

module.exports = router;
`;
    } else {
      return `import express from 'express';
import {
  sendTestEmail,
  requestPasswordReset,
  sendWelcomeEmail,
  sendNotificationEmail
} from '../controllers/emailController.js';
import { authenticateToken } from '../middlewares/auth.js';
import { validateEmail } from '../middlewares/validation.js';

const router = express.Router();

router.post('/test', authenticateToken, sendTestEmail);
router.post('/password-reset', validateEmail, requestPasswordReset);
router.post('/welcome', authenticateToken, sendWelcomeEmail);
router.post('/notification', authenticateToken, sendNotificationEmail);

export default router;
`;
    }
  }

  // ========== FILE UPLOAD SETUP ==========
  async generateFileUploadSetup() {
    const ext = "js";
    const isCJS = this.config.moduleType === "cjs";

    // File Upload Middleware
    const uploadMiddleware = this.getUploadMiddleware();
    await fs.writeFile(
      path.join(this.projectPath, `src/middlewares/upload.${ext}`),
      uploadMiddleware
    );

    // File Upload Controller
    const uploadController = this.getUploadController();
    await fs.writeFile(
      path.join(this.projectPath, `src/controllers/uploadController.${ext}`),
      uploadController
    );

    // File Upload Routes
    const uploadRoutes = this.getUploadRoutes();
    await fs.writeFile(
      path.join(this.projectPath, `src/routes/uploadRoutes.${ext}`),
      uploadRoutes
    );
  }

  getUploadMiddleware() {
    const isCJS = this.config.moduleType === "cjs";

    if (isCJS) {
      return `const multer = require('multer');
const path = require('path');
const fs = require('fs');

const uploadsDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Only image, PDF, and document files are allowed'));
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: fileFilter
});

const singleUpload = upload.single('file');
const multipleUpload = upload.array('files', 5);

module.exports = { singleUpload, multipleUpload };
`;
    } else {
      return `import multer from 'multer';
import path from 'path';
import fs from 'fs';

const uploadsDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Only image, PDF, and document files are allowed'));
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: fileFilter
});

export const singleUpload = upload.single('file');
export const multipleUpload = upload.array('files', 5);
`;
    }
  }

  getUploadController() {
    const isCJS = this.config.moduleType === "cjs";

    if (isCJS) {
      return `const { singleUpload, multipleUpload } = require('../middlewares/upload.js');

const uploadFile = async (req, res) => {
  try {
    singleUpload(req, res, async (err) => {
      if (err) {
        return res.status(400).json({
          success: false,
          error: err.message
        });
      }

      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: 'Please select a file to upload'
        });
      }

      res.json({
        success: true,
        message: 'File uploaded successfully',
        file: {
          filename: req.file.filename,
          originalName: req.file.originalname,
          size: req.file.size,
          url: \`/uploads/\${req.file.filename}\`
        }
      });
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

const uploadMultipleFiles = async (req, res) => {
  try {
    multipleUpload(req, res, async (err) => {
      if (err) {
        return res.status(400).json({
          success: false,
          error: err.message
        });
      }

      if (!req.files || req.files.length === 0) {
        return res.status(400).json({
          success: false,
          error: 'Please select files to upload'
        });
      }

      const files = req.files.map(file => ({
        filename: file.filename,
        originalName: file.originalname,
        size: file.size,
        url: \`/uploads/\${file.filename}\`
      }));

      res.json({
        success: true,
        message: 'Files uploaded successfully',
        files
      });
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

module.exports = {
  uploadFile,
  uploadMultipleFiles
};
`;
    } else {
      return `import { singleUpload, multipleUpload } from '../middlewares/upload.js';

export const uploadFile = async (req, res) => {
  try {
    singleUpload(req, res, async (err) => {
      if (err) {
        return res.status(400).json({
          success: false,
          error: err.message
        });
      }

      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: 'Please select a file to upload'
        });
      }

      res.json({
        success: true,
        message: 'File uploaded successfully',
        file: {
          filename: req.file.filename,
          originalName: req.file.originalname,
          size: req.file.size,
          url: \`/uploads/\${req.file.filename}\`
        }
      });
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

export const uploadMultipleFiles = async (req, res) => {
  try {
    multipleUpload(req, res, async (err) => {
      if (err) {
        return res.status(400).json({
          success: false,
          error: err.message
        });
      }

      if (!req.files || req.files.length === 0) {
        return res.status(400).json({
          success: false,
          error: 'Please select files to upload'
        });
      }

      const files = req.files.map(file => ({
        filename: file.filename,
        originalName: file.originalname,
        size: file.size,
        url: \`/uploads/\${file.filename}\`
      }));

      res.json({
        success: true,
        message: 'Files uploaded successfully',
        files
      });
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};
`;
    }
  }

  getUploadRoutes() {
    const isCJS = this.config.moduleType === "cjs";

    if (isCJS) {
      return `const express = require('express');
const { uploadFile, uploadMultipleFiles } = require('../controllers/uploadController.js');
const { authenticateToken } = require('../middlewares/auth.js');

const router = express.Router();

router.post('/single', authenticateToken, uploadFile);
router.post('/multiple', authenticateToken, uploadMultipleFiles);

module.exports = router;
`;
    } else {
      return `import express from 'express';
import { uploadFile, uploadMultipleFiles } from '../controllers/uploadController.js';
import { authenticateToken } from '../middlewares/auth.js';

const router = express.Router();

router.post('/single', authenticateToken, uploadFile);
router.post('/multiple', authenticateToken, uploadMultipleFiles);

export default router;
`;
    }
  }

  // ========== VALIDATION SETUP ==========
  async generateValidation() {
    const ext = "js";
    const isCJS = this.config.moduleType === "cjs";

    const validationMiddleware = isCJS ? `const Joi = require('joi');

const validateRegister = (req, res, next) => {
  const schema = Joi.object({
    name: Joi.string().min(2).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  next();
};

const validateLogin = (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  next();
};

const validateEmail = (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email().required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  next();
};

module.exports = {
  validateRegister,
  validateLogin,
  validateEmail
};
` : `import Joi from 'joi';

export const validateRegister = (req, res, next) => {
  const schema = Joi.object({
    name: Joi.string().min(2).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  next();
};

export const validateLogin = (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  next();
};

export const validateEmail = (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email().required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  next();
};
`;

    await fs.writeFile(
      path.join(this.projectPath, `src/middlewares/validation.${ext}`),
      validationMiddleware
    );
  }

  // ========== RATE LIMITING SETUP ==========
  async generateRateLimiting() {
    const ext = "js";
    const isCJS = this.config.moduleType === "cjs";

    const rateLimitMiddleware = isCJS ? `const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = limiter;
` : `import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

export default limiter;
`;

    await fs.writeFile(
      path.join(this.projectPath, `src/middlewares/rateLimit.${ext}`),
      rateLimitMiddleware
    );
  }

  // ========== API DOCS SETUP ==========
  async generateAPIDocs() {
    // Already handled in generateConfigFiles()
  }

  // ========== DOCKER SETUP ==========
  async generateDockerfile() {
    const dockerfile = `FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 3000

CMD ["npm", "start"]
`;

    await fs.writeFile(path.join(this.projectPath, 'Dockerfile'), dockerfile);

    let dockerCompose = `version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
    volumes:
      - .:/app
      - /app/node_modules
`;

    if (this.config.database === 'mongoose') {
      dockerCompose += `
  mongodb:
    image: mongo:latest
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_DATABASE=${this.config.projectName}
    volumes:
      - mongodb_data:/data/db

volumes:
  mongodb_data:
`;
    } else if (this.config.database === 'sequelize') {
      dockerCompose += `
  mysql:
    image: mysql:8.0
    ports:
      - "3306:3306"
    environment:
      - MYSQL_ROOT_PASSWORD=password
      - MYSQL_DATABASE=${this.config.projectName}
    volumes:
      - mysql_data:/var/lib/mysql

volumes:
  mysql_data:
`;
    }

    await fs.writeFile(path.join(this.projectPath, 'docker-compose.yml'), dockerCompose);
  }

  // ========== DATABASE CONFIGURATION ==========
  getDatabaseConfig() {
    const isCJS = this.config.moduleType === "cjs";

    switch (this.config.database) {
      case "mongoose":
        if (isCJS) {
          return `const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI);
    console.log(\`MongoDB Connected: \${conn.connection.host}\`);
  } catch (error) {
    console.error('Database connection error:', error);
    process.exit(1);
  }
};

module.exports = connectDB;
`;
        } else {
          return `import mongoose from 'mongoose';

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI);
    console.log(\`MongoDB Connected: \${conn.connection.host}\`);
  } catch (error) {
    console.error('Database connection error:', error);
    process.exit(1);
  }
};

export default connectDB;
`;
        }

      case "sequelize":
        if (isCJS) {
          return `const { Sequelize } = require('sequelize');

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASS,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'mysql',
    logging: process.env.NODE_ENV === 'development' ? console.log : false,
  }
);

const connectDB = async () => {
  try {
    await sequelize.authenticate();
    console.log('Database connection established successfully.');
    
    // Sync database (remove in production)
    if (process.env.NODE_ENV === 'development') {
      await sequelize.sync({ alter: true });
      console.log('Database synced successfully.');
    }
  } catch (error) {
    console.error('Unable to connect to the database:', error);
    process.exit(1);
  }
};

module.exports = { sequelize, connectDB };
`;
        } else {
          return `import { Sequelize } from 'sequelize';
                 import dotenv from 'dotenv';
                 
                 
dotenv.config();
export const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASS,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'mysql',
    logging: process.env.NODE_ENV === 'development' ? console.log : false,
  }
);

const connectDB = async () => {
  try {
    await sequelize.authenticate();
    console.log('Database connection established successfully.');
    
    // Sync database (remove in production)
    if (process.env.NODE_ENV === 'development') {
      await sequelize.sync({ alter: true });
      console.log('Database synced successfully.');
    }
  } catch (error) {
    console.error('Unable to connect to the database:', error);
    process.exit(1);
  }
};

export default connectDB;
`;
        }

      case "prisma":
        if (isCJS) {
          return `const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const connectDB = async () => {
  try {
    await prisma.$connect();
    console.log('Database connected successfully with Prisma.');
  } catch (error) {
    console.error('Prisma connection error:', error);
    process.exit(1);
  }
};

module.exports = connectDB;
`;
        } else {
          return `import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export const connectDB = async () => {
  try {
    await prisma.$connect();
    console.log('Database connected successfully with Prisma.');
  } catch (error) {
    console.error('Prisma connection error:', error);
    process.exit(1);
  }
};

export default prisma;
`;
        }

      default:
        return "";
    }
  }

  getUserModel() {
    const isCJS = this.config.moduleType === "cjs";

    switch (this.config.database) {
      case "mongoose":
        if (isCJS) {
          return `const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  }
}, {
  timestamps: true
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
`;
        } else {
          return `import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  }
}, {
  timestamps: true
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

export default mongoose.model('User', userSchema);
`;
        }

      case "sequelize":
        if (isCJS) {
          return `const { DataTypes } = require('sequelize');
const {sequelize} = require('../config/database.js');
const bcrypt = require('bcryptjs');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: true,
      len: [2, 50]
    }
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true
    }
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [6]
    }
  }
}, {
  timestamps: true,
  hooks: {
    beforeSave: async (user) => {
      if (user.changed('password')) {
        user.password = await bcrypt.hash(user.password, 12);
      }
    }
  }
});

User.prototype.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = User;
`;
        } else {
          return `import { DataTypes } from 'sequelize';
import {sequelize} from '../config/database.js';
import bcrypt from 'bcryptjs';

const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: true,
      len: [2, 50]
    }
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true
    }
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [6]
    }
  }
}, {
  timestamps: true,
  hooks: {
    beforeSave: async (user) => {
      if (user.changed('password')) {
        user.password = await bcrypt.hash(user.password, 12);
      }
    }
  }
});

User.prototype.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

export default User;
`;
        }

      case "prisma":
        if (isCJS) {
          return `const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

// Extend Prisma Client with custom methods
class User {
  static async createUser(userData) {
    const hashedPassword = await bcrypt.hash(userData.password, 12);
    return await prisma.user.create({
      data: {
        ...userData,
        password: hashedPassword
      }
    });
  }

  static async findUserByEmail(email) {
    return await prisma.user.findUnique({
      where: { email }
    });
  }

  static async findUserById(id) {
    return await prisma.user.findUnique({
      where: { id }
    });
  }

  static async comparePassword(user, candidatePassword) {
    return await bcrypt.compare(candidatePassword, user.password);
  }
}

module.exports = { User, prisma };
`;
        } else {
          return `import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

// Extend Prisma Client with custom methods
export class User {
  static async createUser(userData) {
    const hashedPassword = await bcrypt.hash(userData.password, 12);
    return await prisma.user.create({
      data: {
        ...userData,
        password: hashedPassword
      }
    });
  }

  static async findUserByEmail(email) {
    return await prisma.user.findUnique({
      where: { email }
    });
  }

  static async findUserById(id) {
    return await prisma.user.findUnique({
      where: { id }
    });
  }

  static async comparePassword(user, candidatePassword) {
    return await bcrypt.compare(candidatePassword, user.password);
  }
}

export default prisma;
`;
        }

      default:
        return "";
    }
  }

  getFileModel() {
    const isCJS = this.config.moduleType === "cjs";

    switch (this.config.database) {
      case "mongoose":
        if (isCJS) {
          return `const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  filename: {
    type: String,
    required: true
  },
  originalName: {
    type: String,
    required: true
  },
  mimetype: {
    type: String,
    required: true
  },
  size: {
    type: Number,
    required: true
  },
  path: {
    type: String,
    required: true
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('File', fileSchema);
`;
        } else {
          return `import mongoose from 'mongoose';

const fileSchema = new mongoose.Schema({
  filename: {
    type: String,
    required: true
  },
  originalName: {
    type: String,
    required: true
  },
  mimetype: {
    type: String,
    required: true
  },
  size: {
    type: Number,
    required: true
  },
  path: {
    type: String,
    required: true
  }
}, {
  timestamps: true
});

export default mongoose.model('File', fileSchema);
`;
        }

      case "sequelize":
        if (isCJS) {
          return `const { DataTypes } = require('sequelize');
const {sequelize} = require('../config/database.js');

const File = sequelize.define('File', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  filename: {
    type: DataTypes.STRING,
    allowNull: false
  },
  originalName: {
    type: DataTypes.STRING,
    allowNull: false
  },
  mimetype: {
    type: DataTypes.STRING,
    allowNull: false
  },
  size: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  path: {
    type: DataTypes.STRING,
    allowNull: false
  }
}, {
  timestamps: true
});

module.exports = File;
`;
        } else {
          return `import { DataTypes } from 'sequelize';
import {sequelize} from '../config/database.js';

const File = sequelize.define('File', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  filename: {
    type: DataTypes.STRING,
    allowNull: false
  },
  originalName: {
    type: DataTypes.STRING,
    allowNull: false
  },
  mimetype: {
    type: DataTypes.STRING,
    allowNull: false
  },
  size: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  path: {
    type: DataTypes.STRING,
    allowNull: false
  }
}, {
  timestamps: true
});

export default File;
`;
        }

      case "prisma":
        // For Prisma, the File model is already defined in schema.prisma
        return "";

      default:
        return "";
    }
  }

  getPackageJson() {
    const basePackage = super.getPackageJson();

    // Add feature-specific dependencies
    if (this.config.features.includes("docs")) {
      basePackage.dependencies["swagger-jsdoc"] = "^6.0.0";
      basePackage.dependencies["swagger-ui-express"] = "^4.0.0";
    }

    if (this.config.features.includes("rateLimit")) {
      basePackage.dependencies["express-rate-limit"] = "^6.0.0";
    }

    if (this.config.features.includes("validation")) {
      basePackage.dependencies["joi"] = "^17.0.0";
    }

    return basePackage;
  }

  getEnvContent() {
    let env = super.getEnvContent();

    if (this.config.features.includes("email")) {
      env += `SMTP_FROM=noreply@yourapp.com
CLIENT_URL=http://localhost:3000\n`;
    }

    if (this.config.database === "prisma") {
      env += `DATABASE_URL="mysql://root:password@localhost:3306/${this.config.projectName}"\n`;
    }

    return env;
  }
}