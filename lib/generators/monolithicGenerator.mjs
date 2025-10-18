import { BaseGenerator } from './baseGenerator.mjs';
import fs from 'fs-extra';
import path from 'path';

export class MonolithicGenerator extends BaseGenerator {
  async generate() {
    await this.ensureDirectory(this.projectPath);
    
    // Create directory structure
    const dirs = [
      'src/controllers',
      'src/models',
      'src/routes',
      'src/middlewares',
      'src/services',
      'src/utils',
      'src/config',
      'uploads',
      'tests'
    ];

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
    
    // Generate Dockerfile if selected
    if (this.config.features.includes('docker')) {
      await this.generateDockerfile();
    }
  }

  async generatePackageJson() {
    const packageJson = this.getPackageJson();
    await fs.writeJson(path.join(this.projectPath, 'package.json'), packageJson, { spaces: 2 });
  }

  async generateServerFile() {
    const serverTemplate = `import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';

// Import routes
import authRoutes from './src/routes/authRoutes.js';
import userRoutes from './src/routes/userRoutes.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files
app.use('/uploads', express.static('uploads'));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

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
  console.log(\`📊 Environment: \${process.env.NODE_ENV}\`);
});

export default app;
`;

    const fileName = this.config.moduleType === 'mjs' ? 'server.mjs' : 'server.js';
    await fs.writeFile(path.join(this.projectPath, fileName), serverTemplate);
  }

  async generateEnvFile() {
    const envContent = this.getEnvContent();
    await fs.writeFile(path.join(this.projectPath, '.env'), envContent);
    await fs.writeFile(path.join(this.projectPath, '.env.example'), envContent);
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
    await fs.writeFile(path.join(this.projectPath, '.gitignore'), gitignore);
    await fs.writeFile(path.join(this.projectPath, 'uploads/.gitkeep'), '');
  }

  async generateConfigFiles() {
    // Database config
    if (this.config.database !== 'none') {
      const dbConfig = this.getDatabaseConfig();
      const ext = this.config.moduleType === 'mjs' ? 'js' : 'js';
      await fs.writeFile(
        path.join(this.projectPath, `src/config/database.${ext}`), 
        dbConfig
      );
    }

    // Auth middleware
    if (this.config.features.includes('auth')) {
      const authMiddleware = `import jwt from 'jsonwebtoken';

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
      const ext = this.config.moduleType === 'mjs' ? 'js' : 'js';
      await fs.writeFile(
        path.join(this.projectPath, `src/middlewares/auth.${ext}`), 
        authMiddleware
      );
    }
  }

  async generateBasicStructure() {
    const ext = this.config.moduleType === 'mjs' ? 'js' : 'js';

    // Basic user model
    if (this.config.database !== 'none') {
      const userModel = this.getUserModel();
      await fs.writeFile(
        path.join(this.projectPath, `src/models/User.${ext}`), 
        userModel
      );
    }

    // Basic controller
    const userController = `export const getUsers = async (req, res) => {
  try {
    // Implementation here
    res.json({ message: 'Get users endpoint' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    // Implementation here
    res.json({ message: \`Get user \${id}\` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
`;
    await fs.writeFile(
      path.join(this.projectPath, `src/controllers/userController.${ext}`), 
      userController
    );

    // Basic routes
    const userRoutes = `import express from 'express';
import { getUsers, getUserById } from '../controllers/userController.js';
import { authenticateToken } from '../middlewares/auth.js';

const router = express.Router();

router.get('/', authenticateToken, getUsers);
router.get('/:id', authenticateToken, getUserById);

export default router;
`;
    await fs.writeFile(
      path.join(this.projectPath, `src/routes/userRoutes.${ext}`), 
      userRoutes
    );

    // Auth routes
    if (this.config.features.includes('auth')) {
      const authRoutes = `import express from 'express';
import { register, login } from '../controllers/authController.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);

export default router;
`;
      await fs.writeFile(
        path.join(this.projectPath, `src/routes/authRoutes.${ext}`), 
        authRoutes
      );

      // Auth controller
      const authController = `import jwt from 'jsonwebtoken';
import User from '../models/User.js';

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Create user
    const user = new User({ name, email, password });
    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
`;
      await fs.writeFile(
        path.join(this.projectPath, `src/controllers/authController.${ext}`), 
        authController
      );
    }
  }

  getDatabaseConfig() {
    switch (this.config.database) {
      case 'mongoose':
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

      case 'sequelize':
        return `import { Sequelize } from 'sequelize';

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

export const connectDB = async () => {
  try {
    await sequelize.authenticate();
    console.log('Database connection established successfully.');
  } catch (error) {
    console.error('Unable to connect to the database:', error);
    process.exit(1);
  }
};

export default sequelize;
`;

      default:
        return '';
    }
  }

  getUserModel() {
    switch (this.config.database) {
      case 'mongoose':
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

      case 'sequelize':
        return `import { DataTypes } from 'sequelize';
import sequelize from '../config/database.js';
import bcrypt from 'bcryptjs';

const User = sequelize.define('User', {
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    trim: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    lowercase: true,
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

      default:
        return '';
    }
  }

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

    // Docker compose
    const dockerCompose = `version: '3.8'
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
    depends_on:
      - mongodb

  mongodb:
    image: mongo:latest
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_DATABASE=myapp
    volumes:
      - mongodb_data:/data/db

volumes:
  mongodb_data:
`;

    await fs.writeFile(path.join(this.projectPath, 'docker-compose.yml'), dockerCompose);
  }
}