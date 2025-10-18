import { BaseGenerator } from './baseGenerator.mjs';
import fs from 'fs-extra';
import path from 'path';

export class MicroserviceGenerator extends BaseGenerator {
  async generate() {
    await this.ensureDirectory(this.projectPath);
    
    // Create microservices root structure
    const rootDirs = [
      'api-gateway',
      'service-discovery',
      'shared',
      'docker',
      'kubernetes',
      'scripts',
      'docs'
    ];

    for (const dir of rootDirs) {
      await this.ensureDirectory(path.join(this.projectPath, dir));
    }

    // Create individual services
    for (const service of this.config.microservices.services) {
      await this.generateMicroservice(service);
    }

    // Generate shared components
    await this.generateSharedComponents();
    
    // Generate API Gateway
    if (this.config.microservices.includeApiGateway) {
      await this.generateApiGateway();
    }

    // Generate Service Discovery
    if (this.config.microservices.includeServiceDiscovery) {
      await this.generateServiceDiscovery();
    }

    // Generate Docker configuration
    await this.generateDockerSetup();

    // Generate root configuration
    await this.generateRootConfig();
  }

  async generateMicroservice(serviceName) {
    const servicePath = path.join(this.projectPath, `services/${serviceName}-service`);
    
    const serviceDirs = [
      'src/controllers',
      'src/models',
      'src/routes',
      'src/middlewares',
      'src/services',
      'src/utils',
      'src/config',
      'src/queues',
      'tests',
      'migrations'
    ];

    for (const dir of serviceDirs) {
      await this.ensureDirectory(path.join(servicePath, dir));
    }

    // Generate service-specific files
    await this.generateServicePackageJson(serviceName, servicePath);
    await this.generateServiceServer(serviceName, servicePath);
    await this.generateServiceDockerfile(serviceName, servicePath);
    await this.generateServiceConfig(serviceName, servicePath);
    
    // Generate service-specific logic
    switch (serviceName) {
      case 'auth':
        await this.generateAuthService(servicePath);
        break;
      case 'user':
        await this.generateUserService(servicePath);
        break;
      case 'notification':
        await this.generateNotificationService(servicePath);
        break;
      case 'file':
        await this.generateFileService(servicePath);
        break;
      case 'payment':
        await this.generatePaymentService(servicePath);
        break;
      case 'analytics':
        await this.generateAnalyticsService(servicePath);
        break;
    }
  }
async generateUserService(servicePath) {
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  // User Controller
  const userController = isCJS ? `const { User } = require('../models/User');
const { redis } = require('../config/redis');

class UserController {
  async getProfile(req, res) {
    try {
      const { userId } = req.user;

      // Try to get from cache first
      const cachedUser = await redis.get(\`user:\${userId}\`);
      if (cachedUser) {
        return res.json({
          success: true,
          data: JSON.parse(cachedUser)
        });
      }

      const user = await User.findById(userId)
        .select('-password -__v')
        .lean();

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Cache user data for 5 minutes
      await redis.setex(\`user:\${userId}\`, 300, JSON.stringify(user));

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
  }

  async updateProfile(req, res) {
    try {
      const { userId } = req.user;
      const { name, email, phone, avatar } = req.body;

      const user = await User.findByIdAndUpdate(
        userId,
        { name, email, phone, avatar },
        { new: true, runValidators: true }
      ).select('-password -__v');

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Invalidate cache
      await redis.del(\`user:\${userId}\`);

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: user
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getAllUsers(req, res) {
    try {
      const { page = 1, limit = 10, search } = req.query;
      const skip = (page - 1) * limit;

      let query = {};
      if (search) {
        query = {
          $or: [
            { name: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } }
          ]
        };
      }

      const users = await User.find(query)
        .select('-password -__v')
        .skip(skip)
        .limit(parseInt(limit))
        .sort({ createdAt: -1 });

      const total = await User.countDocuments(query);

      res.json({
        success: true,
        data: {
          users,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: Math.ceil(total / limit)
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getUserById(req, res) {
    try {
      const { id } = req.params;

      const user = await User.findById(id).select('-password -__v');
      
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

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
  }

  async deleteUser(req, res) {
    try {
      const { id } = req.params;

      const user = await User.findByIdAndDelete(id);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Invalidate cache
      await redis.del(\`user:\${id}\`);

      res.json({
        success: true,
        message: 'User deleted successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
}

module.exports = new UserController();
` : `import { User } from '../models/User.js';
import { redis } from '../config/redis.js';

export class UserController {
  async getProfile(req, res) {
    try {
      const { userId } = req.user;

      const cachedUser = await redis.get(\`user:\${userId}\`);
      if (cachedUser) {
        return res.json({
          success: true,
          data: JSON.parse(cachedUser)
        });
      }

      const user = await User.findById(userId)
        .select('-password -__v')
        .lean();

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      await redis.setex(\`user:\${userId}\`, 300, JSON.stringify(user));

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
  }

  async updateProfile(req, res) {
    try {
      const { userId } = req.user;
      const { name, email, phone, avatar } = req.body;

      const user = await User.findByIdAndUpdate(
        userId,
        { name, email, phone, avatar },
        { new: true, runValidators: true }
      ).select('-password -__v');

      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      await redis.del(\`user:\${userId}\`);

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: user
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getAllUsers(req, res) {
    try {
      const { page = 1, limit = 10, search } = req.query;
      const skip = (page - 1) * limit;

      let query = {};
      if (search) {
        query = {
          $or: [
            { name: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } }
          ]
        };
      }

      const users = await User.find(query)
        .select('-password -__v')
        .skip(skip)
        .limit(parseInt(limit))
        .sort({ createdAt: -1 });

      const total = await User.countDocuments(query);

      res.json({
        success: true,
        data: {
          users,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: Math.ceil(total / limit)
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getUserById(req, res) {
    try {
      const { id } = req.params;

      const user = await User.findById(id).select('-password -__v');
      
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

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
  }

  async deleteUser(req, res) {
    try {
      const { id } = req.params;

      const user = await User.findByIdAndDelete(id);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      await redis.del(\`user:\${id}\`);

      res.json({
        success: true,
        message: 'User deleted successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
}

export default new UserController();
`;

  await fs.writeFile(
    path.join(servicePath, `src/controllers/UserController.${ext}`),
    userController
  );

  // User Model
  const userModel = isCJS ? `const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [100, 'Name cannot exceed 100 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\\w+([.-]?\\w+)*@\\w+([.-]?\\w+)*(\\.\\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  phone: {
    type: String,
    trim: true
  },
  avatar: {
    type: String,
    default: null
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date,
    default: null
  },
  preferences: {
    notifications: {
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: true },
      sms: { type: Boolean, default: false }
    },
    language: { type: String, default: 'en' },
    timezone: { type: String, default: 'UTC' }
  }
}, {
  timestamps: true
});

// Index for better query performance
userSchema.index({ email: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ name: 'text', email: 'text' });

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Update last login method
userSchema.methods.updateLastLogin = async function() {
  this.lastLogin = new Date();
  await this.save();
};

// Remove password from JSON output
userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  delete user.__v;
  return user;
};

module.exports = mongoose.model('User', userSchema);
` : `import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [100, 'Name cannot exceed 100 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\\w+([.-]?\\w+)*@\\w+([.-]?\\w+)*(\\.\\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  phone: {
    type: String,
    trim: true
  },
  avatar: {
    type: String,
    default: null
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date,
    default: null
  },
  preferences: {
    notifications: {
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: true },
      sms: { type: Boolean, default: false }
    },
    language: { type: String, default: 'en' },
    timezone: { type: String, default: 'UTC' }
  }
}, {
  timestamps: true
});

userSchema.index({ email: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ name: 'text', email: 'text' });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.updateLastLogin = async function() {
  this.lastLogin = new Date();
  await this.save();
};

userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  delete user.__v;
  return user;
};

export const User = mongoose.model('User', userSchema);
`;

  await fs.writeFile(
    path.join(servicePath, `src/models/User.${ext}`),
    userModel
  );
}

async generateFileService(servicePath) {
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  // File Controller
  const fileController = isCJS ? `const multer = require('multer');
const path = require('path');
const fs = require('fs-extra');
const { File } = require('../models/File');

class FileController {
  constructor() {
    this.storage = multer.diskStorage({
      destination: async (req, file, cb) => {
        const uploadDir = \`uploads/\${req.user?.userId || 'anonymous'}\`;
        await fs.ensureDir(uploadDir);
        cb(null, uploadDir);
      },
      filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
      }
    });

    this.upload = multer({
      storage: this.storage,
      limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
      },
      fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|mp4|mp3/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (mimetype && extname) {
          return cb(null, true);
        } else {
          cb(new Error('Invalid file type'));
        }
      }
    });
  }

  async uploadFile(req, res) {
    try {
      const { originalname, filename, path: filePath, size, mimetype } = req.file;
      const { userId } = req.user;

      const file = await File.create({
        filename: originalname,
        storageName: filename,
        path: filePath,
        size,
        mimetype,
        uploadedBy: userId,
        metadata: req.body.metadata ? JSON.parse(req.body.metadata) : {}
      });

      res.status(201).json({
        success: true,
        message: 'File uploaded successfully',
        data: {
          file: {
            id: file._id,
            filename: file.filename,
            url: \`/api/file/download/\${file._id}\`,
            size: file.size,
            mimetype: file.mimetype,
            uploadedAt: file.createdAt
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async uploadMultiple(req, res) {
    try {
      const { userId } = req.user;
      const files = req.files;

      const uploadedFiles = await Promise.all(
        files.map(async (file) => {
          const { originalname, filename, path: filePath, size, mimetype } = file;
          
          return await File.create({
            filename: originalname,
            storageName: filename,
            path: filePath,
            size,
            mimetype,
            uploadedBy: userId,
            metadata: req.body.metadata ? JSON.parse(req.body.metadata) : {}
          });
        })
      );

      res.status(201).json({
        success: true,
        message: \`\${files.length} files uploaded successfully\`,
        data: {
          files: uploadedFiles.map(file => ({
            id: file._id,
            filename: file.filename,
            url: \`/api/file/download/\${file._id}\`,
            size: file.size,
            mimetype: file.mimetype,
            uploadedAt: file.createdAt
          }))
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async downloadFile(req, res) {
    try {
      const { id } = req.params;

      const file = await File.findById(id);
      if (!file) {
        return res.status(404).json({
          success: false,
          error: 'File not found'
        });
      }

      // Check permissions (basic implementation)
      if (file.uploadedBy.toString() !== req.user.userId && req.user.role !== 'admin') {
        return res.status(403).json({
          success: false,
          error: 'Access denied'
        });
      }

      res.setHeader('Content-Type', file.mimetype);
      res.setHeader('Content-Disposition', \`attachment; filename="\${file.filename}"\`);
      
      const fileStream = fs.createReadStream(file.path);
      fileStream.pipe(res);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getFileInfo(req, res) {
    try {
      const { id } = req.params;

      const file = await File.findById(id).populate('uploadedBy', 'name email');
      if (!file) {
        return res.status(404).json({
          success: false,
          error: 'File not found'
        });
      }

      res.json({
        success: true,
        data: { file }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getUserFiles(req, res) {
    try {
      const { userId } = req.user;
      const { page = 1, limit = 10, type } = req.query;
      const skip = (page - 1) * limit;

      let query = { uploadedBy: userId };
      if (type) {
        query.mimetype = new RegExp(type, 'i');
      }

      const files = await File.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit));

      const total = await File.countDocuments(query);

      res.json({
        success: true,
        data: {
          files,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: Math.ceil(total / limit)
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async deleteFile(req, res) {
    try {
      const { id } = req.params;
      const { userId, role } = req.user;

      const file = await File.findById(id);
      if (!file) {
        return res.status(404).json({
          success: false,
          error: 'File not found'
        });
      }

      // Check permissions
      if (file.uploadedBy.toString() !== userId && role !== 'admin') {
        return res.status(403).json({
          success: false,
          error: 'Access denied'
        });
      }

      // Delete physical file
      await fs.remove(file.path);

      // Delete database record
      await File.findByIdAndDelete(id);

      res.json({
        success: true,
        message: 'File deleted successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
}

module.exports = new FileController();
` : `import multer from 'multer';
import path from 'path';
import fs from 'fs-extra';
import { File } from '../models/File.js';

export class FileController {
  constructor() {
    this.storage = multer.diskStorage({
      destination: async (req, file, cb) => {
        const uploadDir = \`uploads/\${req.user?.userId || 'anonymous'}\`;
        await fs.ensureDir(uploadDir);
        cb(null, uploadDir);
      },
      filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
      }
    });

    this.upload = multer({
      storage: this.storage,
      limits: {
        fileSize: 10 * 1024 * 1024
      },
      fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|mp4|mp3/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (mimetype && extname) {
          return cb(null, true);
        } else {
          cb(new Error('Invalid file type'));
        }
      }
    });
  }

  async uploadFile(req, res) {
    try {
      const { originalname, filename, path: filePath, size, mimetype } = req.file;
      const { userId } = req.user;

      const file = await File.create({
        filename: originalname,
        storageName: filename,
        path: filePath,
        size,
        mimetype,
        uploadedBy: userId,
        metadata: req.body.metadata ? JSON.parse(req.body.metadata) : {}
      });

      res.status(201).json({
        success: true,
        message: 'File uploaded successfully',
        data: {
          file: {
            id: file._id,
            filename: file.filename,
            url: \`/api/file/download/\${file._id}\`,
            size: file.size,
            mimetype: file.mimetype,
            uploadedAt: file.createdAt
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async uploadMultiple(req, res) {
    try {
      const { userId } = req.user;
      const files = req.files;

      const uploadedFiles = await Promise.all(
        files.map(async (file) => {
          const { originalname, filename, path: filePath, size, mimetype } = file;
          
          return await File.create({
            filename: originalname,
            storageName: filename,
            path: filePath,
            size,
            mimetype,
            uploadedBy: userId,
            metadata: req.body.metadata ? JSON.parse(req.body.metadata) : {}
          });
        })
      );

      res.status(201).json({
        success: true,
        message: \`\${files.length} files uploaded successfully\`,
        data: {
          files: uploadedFiles.map(file => ({
            id: file._id,
            filename: file.filename,
            url: \`/api/file/download/\${file._id}\`,
            size: file.size,
            mimetype: file.mimetype,
            uploadedAt: file.createdAt
          }))
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async downloadFile(req, res) {
    try {
      const { id } = req.params;

      const file = await File.findById(id);
      if (!file) {
        return res.status(404).json({
          success: false,
          error: 'File not found'
        });
      }

      if (file.uploadedBy.toString() !== req.user.userId && req.user.role !== 'admin') {
        return res.status(403).json({
          success: false,
          error: 'Access denied'
        });
      }

      res.setHeader('Content-Type', file.mimetype);
      res.setHeader('Content-Disposition', \`attachment; filename="\${file.filename}"\`);
      
      const fileStream = fs.createReadStream(file.path);
      fileStream.pipe(res);
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getFileInfo(req, res) {
    try {
      const { id } = req.params;

      const file = await File.findById(id).populate('uploadedBy', 'name email');
      if (!file) {
        return res.status(404).json({
          success: false,
          error: 'File not found'
        });
      }

      res.json({
        success: true,
        data: { file }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getUserFiles(req, res) {
    try {
      const { userId } = req.user;
      const { page = 1, limit = 10, type } = req.query;
      const skip = (page - 1) * limit;

      let query = { uploadedBy: userId };
      if (type) {
        query.mimetype = new RegExp(type, 'i');
      }

      const files = await File.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit));

      const total = await File.countDocuments(query);

      res.json({
        success: true,
        data: {
          files,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: Math.ceil(total / limit)
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async deleteFile(req, res) {
    try {
      const { id } = req.params;
      const { userId, role } = req.user;

      const file = await File.findById(id);
      if (!file) {
        return res.status(404).json({
          success: false,
          error: 'File not found'
        });
      }

      if (file.uploadedBy.toString() !== userId && role !== 'admin') {
        return res.status(403).json({
          success: false,
          error: 'Access denied'
        });
      }

      await fs.remove(file.path);
      await File.findByIdAndDelete(id);

      res.json({
        success: true,
        message: 'File deleted successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
}

export default new FileController();
`;

  await fs.writeFile(
    path.join(servicePath, `src/controllers/FileController.${ext}`),
    fileController
  );

  // File Model
  const fileModel = isCJS ? `const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  filename: {
    type: String,
    required: [true, 'Filename is required'],
    trim: true
  },
  storageName: {
    type: String,
    required: true
  },
  path: {
    type: String,
    required: true
  },
  size: {
    type: Number,
    required: true
  },
  mimetype: {
    type: String,
    required: true
  },
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed,
    default: {}
  },
  isPublic: {
    type: Boolean,
    default: false
  },
  downloadCount: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

// Indexes for better performance
fileSchema.index({ uploadedBy: 1, createdAt: -1 });
fileSchema.index({ mimetype: 1 });
fileSchema.index({ createdAt: -1 });

// Virtual for file URL
fileSchema.virtual('url').get(function() {
  return \`/api/file/download/\${this._id}\`;
});

// Method to increment download count
fileSchema.methods.incrementDownloadCount = async function() {
  this.downloadCount += 1;
  await this.save();
};

module.exports = mongoose.model('File', fileSchema);
` : `import mongoose from 'mongoose';

const fileSchema = new mongoose.Schema({
  filename: {
    type: String,
    required: [true, 'Filename is required'],
    trim: true
  },
  storageName: {
    type: String,
    required: true
  },
  path: {
    type: String,
    required: true
  },
  size: {
    type: Number,
    required: true
  },
  mimetype: {
    type: String,
    required: true
  },
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed,
    default: {}
  },
  isPublic: {
    type: Boolean,
    default: false
  },
  downloadCount: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

fileSchema.index({ uploadedBy: 1, createdAt: -1 });
fileSchema.index({ mimetype: 1 });
fileSchema.index({ createdAt: -1 });

fileSchema.virtual('url').get(function() {
  return \`/api/file/download/\${this._id}\`;
});

fileSchema.methods.incrementDownloadCount = async function() {
  this.downloadCount += 1;
  await this.save();
};

export const File = mongoose.model('File', fileSchema);
`;

  await fs.writeFile(
    path.join(servicePath, `src/models/File.${ext}`),
    fileModel
  );
}

async generatePaymentService(servicePath) {
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  // Payment Controller
  const paymentController = isCJS ? `const { Payment } = require('../models/Payment');
const { paymentQueue } = require('../queues/paymentQueue');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

class PaymentController {
  async createPaymentIntent(req, res) {
    try {
      const { amount, currency = 'usd', description, metadata } = req.body;
      const { userId } = req.user;

      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100), // Convert to cents
        currency,
        description,
        metadata: {
          userId,
          ...metadata
        }
      });

      // Create payment record
      const payment = await Payment.create({
        userId,
        amount,
        currency,
        description,
        status: 'pending',
        paymentIntentId: paymentIntent.id,
        metadata
      });

      res.json({
        success: true,
        data: {
          clientSecret: paymentIntent.client_secret,
          paymentId: payment._id,
          amount: payment.amount,
          currency: payment.currency
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async confirmPayment(req, res) {
    try {
      const { paymentId } = req.body;

      const payment = await Payment.findById(paymentId);
      if (!payment) {
        return res.status(404).json({
          success: false,
          error: 'Payment not found'
        });
      }

      const paymentIntent = await stripe.paymentIntents.retrieve(payment.paymentIntentId);

      if (paymentIntent.status === 'succeeded') {
        payment.status = 'completed';
        payment.completedAt = new Date();
        await payment.save();

        // Queue payment confirmation tasks
        await paymentQueue.add('process-payment-success', {
          paymentId: payment._id,
          userId: payment.userId,
          amount: payment.amount
        });

        res.json({
          success: true,
          message: 'Payment confirmed successfully',
          data: { payment }
        });
      } else {
        payment.status = 'failed';
        await payment.save();

        res.status(400).json({
          success: false,
          error: 'Payment not successful'
        });
      }
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getPaymentHistory(req, res) {
    try {
      const { userId } = req.user;
      const { page = 1, limit = 10, status } = req.query;
      const skip = (page - 1) * limit;

      let query = { userId };
      if (status) {
        query.status = status;
      }

      const payments = await Payment.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit));

      const total = await Payment.countDocuments(query);

      res.json({
        success: true,
        data: {
          payments,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: Math.ceil(total / limit)
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getPaymentById(req, res) {
    try {
      const { id } = req.params;
      const { userId, role } = req.user;

      const payment = await Payment.findById(id);
      if (!payment) {
        return res.status(404).json({
          success: false,
          error: 'Payment not found'
        });
      }

      // Check permissions
      if (payment.userId.toString() !== userId && role !== 'admin') {
        return res.status(403).json({
          success: false,
          error: 'Access denied'
        });
      }

      res.json({
        success: true,
        data: { payment }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async refundPayment(req, res) {
    try {
      const { id } = req.params;
      const { reason } = req.body;

      const payment = await Payment.findById(id);
      if (!payment) {
        return res.status(404).json({
          success: false,
          error: 'Payment not found'
        });
      }

      if (payment.status !== 'completed') {
        return res.status(400).json({
          success: false,
          error: 'Only completed payments can be refunded'
        });
      }

      const refund = await stripe.refunds.create({
        payment_intent: payment.paymentIntentId,
        reason: reason || 'requested_by_customer'
      });

      payment.status = 'refunded';
      payment.refundedAt = new Date();
      payment.refundReason = reason;
      await payment.save();

      // Queue refund processing tasks
      await paymentQueue.add('process-refund', {
        paymentId: payment._id,
        userId: payment.userId,
        amount: payment.amount
      });

      res.json({
        success: true,
        message: 'Payment refunded successfully',
        data: { payment, refund }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  // Webhook handler for Stripe events
  async handleWebhook(req, res) {
    try {
      const sig = req.headers['stripe-signature'];
      let event;

      try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
      } catch (err) {
        return res.status(400).json({
          success: false,
          error: \`Webhook Error: \${err.message}\`
        });
      }

      switch (event.type) {
        case 'payment_intent.succeeded':
          const paymentIntent = event.data.object;
          await this.handlePaymentSuccess(paymentIntent);
          break;
        case 'payment_intent.payment_failed':
          const failedPayment = event.data.object;
          await this.handlePaymentFailure(failedPayment);
          break;
        default:
          console.log(\`Unhandled event type: \${event.type}\`);
      }

      res.json({ success: true, received: true });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async handlePaymentSuccess(paymentIntent) {
    try {
      const payment = await Payment.findOne({ paymentIntentId: paymentIntent.id });
      if (payment) {
        payment.status = 'completed';
        payment.completedAt = new Date();
        await payment.save();

        await paymentQueue.add('process-payment-success', {
          paymentId: payment._id,
          userId: payment.userId,
          amount: payment.amount
        });
      }
    } catch (error) {
      console.error('Error handling payment success:', error);
    }
  }

  async handlePaymentFailure(paymentIntent) {
    try {
      const payment = await Payment.findOne({ paymentIntentId: paymentIntent.id });
      if (payment) {
        payment.status = 'failed';
        payment.failureReason = paymentIntent.last_payment_error?.message;
        await payment.save();
      }
    } catch (error) {
      console.error('Error handling payment failure:', error);
    }
  }
}

module.exports = new PaymentController();
` : `import { Payment } from '../models/Payment.js';
import { paymentQueue } from '../queues/paymentQueue.js';
import stripePackage from 'stripe';

const stripe = stripePackage(process.env.STRIPE_SECRET_KEY);

export class PaymentController {
  async createPaymentIntent(req, res) {
    try {
      const { amount, currency = 'usd', description, metadata } = req.body;
      const { userId } = req.user;

      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100),
        currency,
        description,
        metadata: {
          userId,
          ...metadata
        }
      });

      const payment = await Payment.create({
        userId,
        amount,
        currency,
        description,
        status: 'pending',
        paymentIntentId: paymentIntent.id,
        metadata
      });

      res.json({
        success: true,
        data: {
          clientSecret: paymentIntent.client_secret,
          paymentId: payment._id,
          amount: payment.amount,
          currency: payment.currency
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async confirmPayment(req, res) {
    try {
      const { paymentId } = req.body;

      const payment = await Payment.findById(paymentId);
      if (!payment) {
        return res.status(404).json({
          success: false,
          error: 'Payment not found'
        });
      }

      const paymentIntent = await stripe.paymentIntents.retrieve(payment.paymentIntentId);

      if (paymentIntent.status === 'succeeded') {
        payment.status = 'completed';
        payment.completedAt = new Date();
        await payment.save();

        await paymentQueue.add('process-payment-success', {
          paymentId: payment._id,
          userId: payment.userId,
          amount: payment.amount
        });

        res.json({
          success: true,
          message: 'Payment confirmed successfully',
          data: { payment }
        });
      } else {
        payment.status = 'failed';
        await payment.save();

        res.status(400).json({
          success: false,
          error: 'Payment not successful'
        });
      }
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getPaymentHistory(req, res) {
    try {
      const { userId } = req.user;
      const { page = 1, limit = 10, status } = req.query;
      const skip = (page - 1) * limit;

      let query = { userId };
      if (status) {
        query.status = status;
      }

      const payments = await Payment.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit));

      const total = await Payment.countDocuments(query);

      res.json({
        success: true,
        data: {
          payments,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            pages: Math.ceil(total / limit)
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getPaymentById(req, res) {
    try {
      const { id } = req.params;
      const { userId, role } = req.user;

      const payment = await Payment.findById(id);
      if (!payment) {
        return res.status(404).json({
          success: false,
          error: 'Payment not found'
        });
      }

      if (payment.userId.toString() !== userId && role !== 'admin') {
        return res.status(403).json({
          success: false,
          error: 'Access denied'
        });
      }

      res.json({
        success: true,
        data: { payment }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async refundPayment(req, res) {
    try {
      const { id } = req.params;
      const { reason } = req.body;

      const payment = await Payment.findById(id);
      if (!payment) {
        return res.status(404).json({
          success: false,
          error: 'Payment not found'
        });
      }

      if (payment.status !== 'completed') {
        return res.status(400).json({
          success: false,
          error: 'Only completed payments can be refunded'
        });
      }

      const refund = await stripe.refunds.create({
        payment_intent: payment.paymentIntentId,
        reason: reason || 'requested_by_customer'
      });

      payment.status = 'refunded';
      payment.refundedAt = new Date();
      payment.refundReason = reason;
      await payment.save();

      await paymentQueue.add('process-refund', {
        paymentId: payment._id,
        userId: payment.userId,
        amount: payment.amount
      });

      res.json({
        success: true,
        message: 'Payment refunded successfully',
        data: { payment, refund }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async handleWebhook(req, res) {
    try {
      const sig = req.headers['stripe-signature'];
      let event;

      try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
      } catch (err) {
        return res.status(400).json({
          success: false,
          error: \`Webhook Error: \${err.message}\`
        });
      }

      switch (event.type) {
        case 'payment_intent.succeeded':
          const paymentIntent = event.data.object;
          await this.handlePaymentSuccess(paymentIntent);
          break;
        case 'payment_intent.payment_failed':
          const failedPayment = event.data.object;
          await this.handlePaymentFailure(failedPayment);
          break;
        default:
          console.log(\`Unhandled event type: \${event.type}\`);
      }

      res.json({ success: true, received: true });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async handlePaymentSuccess(paymentIntent) {
    try {
      const payment = await Payment.findOne({ paymentIntentId: paymentIntent.id });
      if (payment) {
        payment.status = 'completed';
        payment.completedAt = new Date();
        await payment.save();

        await paymentQueue.add('process-payment-success', {
          paymentId: payment._id,
          userId: payment.userId,
          amount: payment.amount
        });
      }
    } catch (error) {
      console.error('Error handling payment success:', error);
    }
  }

  async handlePaymentFailure(paymentIntent) {
    try {
      const payment = await Payment.findOne({ paymentIntentId: paymentIntent.id });
      if (payment) {
        payment.status = 'failed';
        payment.failureReason = paymentIntent.last_payment_error?.message;
        await payment.save();
      }
    } catch (error) {
      console.error('Error handling payment failure:', error);
    }
  }
}

export default new PaymentController();
`;

  await fs.writeFile(
    path.join(servicePath, `src/controllers/PaymentController.${ext}`),
    paymentController
  );
}

async generateAnalyticsService(servicePath) {
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  // Analytics Controller
  const analyticsController = isCJS ? `const { AnalyticsEvent } = require('../models/AnalyticsEvent');
const { redis } = require('../config/redis');

class AnalyticsController {
  async trackEvent(req, res) {
    try {
      const { eventType, eventData, userId, sessionId } = req.body;

      const event = await AnalyticsEvent.create({
        eventType,
        eventData,
        userId: userId || req.user?.userId,
        sessionId,
        userAgent: req.get('User-Agent'),
        ipAddress: req.ip,
        timestamp: new Date()
      });

      // Update real-time counters in Redis
      await this.updateRealtimeCounters(eventType);

      res.json({
        success: true,
        message: 'Event tracked successfully',
        data: { eventId: event._id }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async updateRealtimeCounters(eventType) {
    const today = new Date().toISOString().split('T')[0];
    
    // Increment daily counter
    await redis.hincrby(\`analytics:daily:\${today}\`, eventType, 1);
    
    // Increment total counter
    await redis.hincrby('analytics:totals', eventType, 1);
    
    // Update real-time dashboard (last 24 hours)
    await redis.zadd('analytics:realtime', Date.now(), \`\${eventType}:\${Date.now()}\`);
    
    // Clean up old real-time data (older than 24 hours)
    const twentyFourHoursAgo = Date.now() - (24 * 60 * 60 * 1000);
    await redis.zremrangebyscore('analytics:realtime', 0, twentyFourHoursAgo);
  }

  async getDashboardStats(req, res) {
    try {
      const { period = '7d' } = req.query;
      
      const [userStats, eventStats, popularEvents] = await Promise.all([
        this.getUserStats(period),
        this.getEventStats(period),
        this.getPopularEvents(period)
      ]);

      res.json({
        success: true,
        data: {
          userStats,
          eventStats,
          popularEvents,
          period
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getUserStats(period) {
    const days = this.getDaysFromPeriod(period);
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const stats = await AnalyticsEvent.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate },
          userId: { $exists: true, $ne: null }
        }
      },
      {
        $group: {
          _id: {
            date: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } },
            userId: '$userId'
          }
        }
      },
      {
        $group: {
          _id: '$_id.date',
          uniqueUsers: { $sum: 1 }
        }
      },
      {
        $sort: { _id: 1 }
      }
    ]);

    return stats;
  }

  async getEventStats(period) {
    const days = this.getDaysFromPeriod(period);
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const stats = await AnalyticsEvent.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$eventType',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);

    return stats;
  }

  async getPopularEvents(period) {
    const days = this.getDaysFromPeriod(period);
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const popularEvents = await AnalyticsEvent.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: {
            eventType: '$eventType',
            date: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } }
          },
          count: { $sum: 1 }
        }
      },
      {
        $group: {
          _id: '$_id.eventType',
          dailyAverage: { $avg: '$count' },
          total: { $sum: '$count' }
        }
      },
      {
        $sort: { total: -1 }
      },
      {
        $limit: 10
      }
    ]);

    return popularEvents;
  }

  async getRealtimeAnalytics(req, res) {
    try {
      const today = new Date().toISOString().split('T')[0];
      
      const [dailyCounts, totalCounts, recentEvents] = await Promise.all([
        redis.hgetall(\`analytics:daily:\${today}\`),
        redis.hgetall('analytics:totals'),
        this.getRecentEvents(50)
      ]);

      res.json({
        success: true,
        data: {
          daily: dailyCounts || {},
          totals: totalCounts || {},
          recentEvents,
          lastUpdated: new Date().toISOString()
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getRecentEvents(limit = 50) {
    const events = await AnalyticsEvent.find()
      .sort({ timestamp: -1 })
      .limit(limit)
      .select('eventType eventData userId timestamp')
      .lean();

    return events;
  }

  getDaysFromPeriod(period) {
    const periodMap = {
      '1d': 1,
      '7d': 7,
      '30d': 30,
      '90d': 90
    };
    return periodMap[period] || 7;
  }

  async exportAnalytics(req, res) {
    try {
      const { startDate, endDate, format = 'json' } = req.query;

      const query = {};
      if (startDate || endDate) {
        query.timestamp = {};
        if (startDate) query.timestamp.$gte = new Date(startDate);
        if (endDate) query.timestamp.$lte = new Date(endDate);
      }

      const events = await AnalyticsEvent.find(query)
        .sort({ timestamp: 1 })
        .select('-__v')
        .lean();

      if (format === 'csv') {
        // Convert to CSV format
        const csv = this.convertToCSV(events);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=analytics-export.csv');
        return res.send(csv);
      }

      res.json({
        success: true,
        data: {
          events,
          metadata: {
            total: events.length,
            startDate: startDate || 'all',
            endDate: endDate || 'all',
            exportedAt: new Date().toISOString()
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  convertToCSV(events) {
    if (events.length === 0) return '';

    const headers = Object.keys(events[0]).join(',');
    const rows = events.map(event => 
      Object.values(event).map(value => 
        typeof value === 'object' ? JSON.stringify(value) : value
      ).join(',')
    );

    return [headers, ...rows].join('\\n');
  }
}

module.exports = new AnalyticsController();
` : `import { AnalyticsEvent } from '../models/AnalyticsEvent.js';
import { redis } from '../config/redis.js';

export class AnalyticsController {
  async trackEvent(req, res) {
    try {
      const { eventType, eventData, userId, sessionId } = req.body;

      const event = await AnalyticsEvent.create({
        eventType,
        eventData,
        userId: userId || req.user?.userId,
        sessionId,
        userAgent: req.get('User-Agent'),
        ipAddress: req.ip,
        timestamp: new Date()
      });

      await this.updateRealtimeCounters(eventType);

      res.json({
        success: true,
        message: 'Event tracked successfully',
        data: { eventId: event._id }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async updateRealtimeCounters(eventType) {
    const today = new Date().toISOString().split('T')[0];
    
    await redis.hincrby(\`analytics:daily:\${today}\`, eventType, 1);
    await redis.hincrby('analytics:totals', eventType, 1);
    await redis.zadd('analytics:realtime', Date.now(), \`\${eventType}:\${Date.now()}\`);
    
    const twentyFourHoursAgo = Date.now() - (24 * 60 * 60 * 1000);
    await redis.zremrangebyscore('analytics:realtime', 0, twentyFourHoursAgo);
  }

  async getDashboardStats(req, res) {
    try {
      const { period = '7d' } = req.query;
      
      const [userStats, eventStats, popularEvents] = await Promise.all([
        this.getUserStats(period),
        this.getEventStats(period),
        this.getPopularEvents(period)
      ]);

      res.json({
        success: true,
        data: {
          userStats,
          eventStats,
          popularEvents,
          period
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getUserStats(period) {
    const days = this.getDaysFromPeriod(period);
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const stats = await AnalyticsEvent.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate },
          userId: { $exists: true, $ne: null }
        }
      },
      {
        $group: {
          _id: {
            date: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } },
            userId: '$userId'
          }
        }
      },
      {
        $group: {
          _id: '$_id.date',
          uniqueUsers: { $sum: 1 }
        }
      },
      {
        $sort: { _id: 1 }
      }
    ]);

    return stats;
  }

  async getEventStats(period) {
    const days = this.getDaysFromPeriod(period);
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const stats = await AnalyticsEvent.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$eventType',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);

    return stats;
  }

  async getPopularEvents(period) {
    const days = this.getDaysFromPeriod(period);
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const popularEvents = await AnalyticsEvent.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: {
            eventType: '$eventType',
            date: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } }
          },
          count: { $sum: 1 }
        }
      },
      {
        $group: {
          _id: '$_id.eventType',
          dailyAverage: { $avg: '$count' },
          total: { $sum: '$count' }
        }
      },
      {
        $sort: { total: -1 }
      },
      {
        $limit: 10
      }
    ]);

    return popularEvents;
  }

  async getRealtimeAnalytics(req, res) {
    try {
      const today = new Date().toISOString().split('T')[0];
      
      const [dailyCounts, totalCounts, recentEvents] = await Promise.all([
        redis.hgetall(\`analytics:daily:\${today}\`),
        redis.hgetall('analytics:totals'),
        this.getRecentEvents(50)
      ]);

      res.json({
        success: true,
        data: {
          daily: dailyCounts || {},
          totals: totalCounts || {},
          recentEvents,
          lastUpdated: new Date().toISOString()
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getRecentEvents(limit = 50) {
    const events = await AnalyticsEvent.find()
      .sort({ timestamp: -1 })
      .limit(limit)
      .select('eventType eventData userId timestamp')
      .lean();

    return events;
  }

  getDaysFromPeriod(period) {
    const periodMap = {
      '1d': 1,
      '7d': 7,
      '30d': 30,
      '90d': 90
    };
    return periodMap[period] || 7;
  }

  async exportAnalytics(req, res) {
    try {
      const { startDate, endDate, format = 'json' } = req.query;

      const query = {};
      if (startDate || endDate) {
        query.timestamp = {};
        if (startDate) query.timestamp.$gte = new Date(startDate);
        if (endDate) query.timestamp.$lte = new Date(endDate);
      }

      const events = await AnalyticsEvent.find(query)
        .sort({ timestamp: 1 })
        .select('-__v')
        .lean();

      if (format === 'csv') {
        const csv = this.convertToCSV(events);
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=analytics-export.csv');
        return res.send(csv);
      }

      res.json({
        success: true,
        data: {
          events,
          metadata: {
            total: events.length,
            startDate: startDate || 'all',
            endDate: endDate || 'all',
            exportedAt: new Date().toISOString()
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  convertToCSV(events) {
    if (events.length === 0) return '';

    const headers = Object.keys(events[0]).join(',');
    const rows = events.map(event => 
      Object.values(event).map(value => 
        typeof value === 'object' ? JSON.stringify(value) : value
      ).join(',')
    );

    return [headers, ...rows].join('\\n');
  }
}

export default new AnalyticsController();
`;

  await fs.writeFile(
    path.join(servicePath, `src/controllers/AnalyticsController.${ext}`),
    analyticsController
  );
}

  async generateServicePackageJson(serviceName, servicePath) {
  const ext = this.config.moduleType === 'cjs' ? 'cjs' : 'js';
  const isCJS = this.config.moduleType === 'cjs';
  
  const packageJson = {
    name: `${serviceName}-service`,
    version: '1.0.0',
    description: `${serviceName} microservice`,
    main: `src/server.${ext}`,
    type: isCJS ? 'commonjs' : 'module',
    scripts: {
      start: `node src/server.${ext}`,
      dev: `nodemon src/server.${ext}`,
      test: 'jest',
      'test:watch': 'jest --watch',
      migrate: 'node migrations/migrate.js'
    },
    dependencies: {
      express: '^4.18.0',
      mongoose: '^7.0.0',
      'dotenv': '^16.0.0',
      'jsonwebtoken': '^9.0.0',
      'bcryptjs': '^2.4.0',
      'cors': '^2.8.5',
      'helmet': '^7.0.0',
      'compression': '^1.7.0',
      'rate-limiter-flexible': '^3.0.0',
      'winston': '^3.8.0',
      ...(this.config.microservices.messageQueue.includes('bullmq') && {
        'bullmq': '^4.0.0',
        'ioredis': '^5.3.0'
      }),
      ...(this.config.microservices.messageQueue.includes('rabbitmq') && {
        'amqplib': '^0.10.0'
      })
    },
    devDependencies: {
      nodemon: '^2.0.0',
      jest: '^29.0.0',
      supertest: '^6.0.0'
    }
  };

  await fs.writeJson(path.join(servicePath, 'package.json'), packageJson, { spaces: 2 });
}

async generateServiceServer(serviceName, servicePath) {
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  const serverContent = isCJS ? `const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('rate-limiter-flexible');
const winston = require('winston');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || ${this.getServicePort(serviceName)};

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Rate limiting
const rateLimiter = new rateLimit.RateLimiterMemory({
  keyGenerator: (req) => req.ip,
  points: 100, // Number of requests
  duration: 60 // Per 60 seconds
});

// Middleware
app.use(helmet());
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting middleware
app.use(async (req, res, next) => {
  try {
    await rateLimiter.consume(req.ip);
    next();
  } catch (rejRes) {
    res.status(429).json({
      success: false,
      error: 'Too many requests'
    });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: '${serviceName} service is healthy',
    timestamp: new Date().toISOString(),
    service: '${serviceName}'
  });
});

// Routes
app.use('/api/${serviceName}', require('./routes/${serviceName}Routes'));

// Database connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/${serviceName}_service');
    logger.info('MongoDB connected successfully');
  } catch (error) {
    logger.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found'
  });
});

const startServer = async () => {
  await connectDB();
  
  app.listen(PORT, () => {
    logger.info(\`${serviceName} service running on port \${PORT}\`);
    console.log(\`${serviceName} service running on port \${PORT}\`);
  });
};

startServer().catch(error => {
  logger.error('Failed to start server:', error);
  process.exit(1);
});

module.exports = app;
` : `import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import winston from 'winston';
import 'dotenv/config';

import ${serviceName}Routes from './routes/${serviceName}Routes.js';

const app = express();
const PORT = process.env.PORT || ${this.getServicePort(serviceName)};

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Rate limiting
const rateLimiter = new RateLimiterMemory({
  keyGenerator: (req) => req.ip,
  points: 100,
  duration: 60
});

// Middleware
app.use(helmet());
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting middleware
app.use(async (req, res, next) => {
  try {
    await rateLimiter.consume(req.ip);
    next();
  } catch (rejRes) {
    res.status(429).json({
      success: false,
      error: 'Too many requests'
    });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: '${serviceName} service is healthy',
    timestamp: new Date().toISOString(),
    service: '${serviceName}'
  });
});

// Routes
app.use('/api/${serviceName}', ${serviceName}Routes);

// Database connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/${serviceName}_service');
    logger.info('MongoDB connected successfully');
  } catch (error) {
    logger.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found'
  });
});

const startServer = async () => {
  await connectDB();
  
  app.listen(PORT, () => {
    logger.info(\`${serviceName} service running on port \${PORT}\`);
    console.log(\`${serviceName} service running on port \${PORT}\`);
  });
};

startServer().catch(error => {
  logger.error('Failed to start server:', error);
  process.exit(1);
});

export default app;
`;

  await fs.writeFile(
    path.join(servicePath, `src/server.${ext}`),
    serverContent
  );
}

async generateServiceDockerfile(serviceName, servicePath) {
  // Make sure servicePath is defined
  if (!servicePath) {
    servicePath = path.join(this.projectPath, `services/${serviceName}-service`);
  }
  
  const dockerfileContent = `FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy source code
COPY src/ ./src/
COPY migrations/ ./migrations/

# Create logs directory
RUN mkdir -p logs

# Expose port
EXPOSE ${this.getServicePort(serviceName)}

# Start the service
CMD ["npm", "start"]
`;

  await fs.writeFile(
    path.join(servicePath, 'Dockerfile'),
    dockerfileContent
  );

  // Also generate a development Dockerfile
  const dockerfileDevContent = `FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (including dev dependencies)
RUN npm install

# Copy source code
COPY src/ ./src/
COPY migrations/ ./migrations/
COPY shared/ ../shared/

# Create logs directory
RUN mkdir -p logs

# Expose port
EXPOSE ${this.getServicePort(serviceName)}

# Start the service with nodemon for development
CMD ["npm", "run", "dev"]
`;

  await fs.writeFile(
    path.join(servicePath, 'Dockerfile.dev'),
    dockerfileDevContent
  );
}


async generateServiceConfig(serviceName, servicePath) {
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  const configContent = isCJS ? `require('dotenv').config();

module.exports = {
  port: process.env.PORT || ${this.getServicePort(serviceName)},
  mongodb: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/${serviceName}_service'
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379'
  },
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET || 'your-access-secret',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d'
  },
  serviceName: '${serviceName}',
  environment: process.env.NODE_ENV || 'development'
};
` : `import 'dotenv/config';

export default {
  port: process.env.PORT || ${this.getServicePort(serviceName)},
  mongodb: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/${serviceName}_service'
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379'
  },
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET || 'your-access-secret',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d'
  },
  serviceName: '${serviceName}',
  environment: process.env.NODE_ENV || 'development'
};
`;

  await fs.writeFile(
    path.join(servicePath, `src/config/config.${ext}`),
    configContent
  );

  // Also generate environment file
  const envContent = `# ${serviceName.toUpperCase()} Service Environment Variables
PORT=${this.getServicePort(serviceName)}
NODE_ENV=development

# Database
MONGODB_URI=mongodb://localhost:27017/${serviceName}_service

# JWT Secrets
JWT_ACCESS_SECRET=your-access-secret-change-in-production
JWT_REFRESH_SECRET=your-refresh-secret-change-in-production
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Redis
REDIS_URL=redis://localhost:6379

# Service URLs
AUTH_SERVICE_URL=http://localhost:3001
USER_SERVICE_URL=http://localhost:3002
NOTIFICATION_SERVICE_URL=http://localhost:3003
`;

  await fs.writeFile(
    path.join(servicePath, '.env.example'),
    envContent
  );
}

  async generateAuthService(servicePath) {
    const ext = 'js';
    const isCJS = this.config.moduleType === 'cjs';

    // Auth Controller
    const authController = isCJS ? `const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { User } = require('../models/User');
const { redis } = require('../config/redis');
const { authQueue } = require('../queues/authQueue');

class AuthController {
  async register(req, res) {
    try {
      const { name, email, password } = req.body;

      // Check if user exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          error: 'User already exists'
        });
      }

      // Create user
      const user = await User.create({ name, email, password });

      // Generate tokens
      const accessToken = jwt.sign(
        { userId: user.id, service: 'auth' },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN }
      );

      const refreshToken = jwt.sign(
        { userId: user.id, service: 'auth' },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN }
      );

      // Store refresh token in Redis
      await redis.set(\`refresh_token:\${user.id}\`, refreshToken, 'EX', 60 * 60 * 24 * 7);

      // Queue welcome email
      await authQueue.add('send-welcome-email', {
        userId: user.id,
        email: user.email,
        name: user.name
      });

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: {
          user: {
            id: user.id,
            name: user.name,
            email: user.email
          },
          tokens: {
            accessToken,
            refreshToken
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async login(req, res) {
    try {
      const { email, password } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({
          success: false,
          error: 'Invalid credentials'
        });
      }

      const isMatch = await user.comparePassword(password);
      if (!isMatch) {
        return res.status(400).json({
          success: false,
          error: 'Invalid credentials'
        });
      }

      const accessToken = jwt.sign(
        { userId: user.id, service: 'auth' },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN }
      );

      const refreshToken = jwt.sign(
        { userId: user.id, service: 'auth' },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN }
      );

      // Update refresh token in Redis
      await redis.set(\`refresh_token:\${user.id}\`, refreshToken, 'EX', 60 * 60 * 24 * 7);

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user.id,
            name: user.name,
            email: user.email
          },
          tokens: {
            accessToken,
            refreshToken
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({
          success: false,
          error: 'Refresh token required'
        });
      }

      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      
      // Verify token exists in Redis
      const storedToken = await redis.get(\`refresh_token:\${decoded.userId}\`);
      if (storedToken !== refreshToken) {
        return res.status(401).json({
          success: false,
          error: 'Invalid refresh token'
        });
      }

      const accessToken = jwt.sign(
        { userId: decoded.userId, service: 'auth' },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN }
      );

      res.json({
        success: true,
        data: { accessToken }
      });
    } catch (error) {
      res.status(401).json({
        success: false,
        error: 'Invalid refresh token'
      });
    }
  }

  async validateToken(req, res) {
    try {
      const { token } = req.body;

      if (!token) {
        return res.status(400).json({
          success: false,
          error: 'Token required'
        });
      }

      const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
      
      res.json({
        success: true,
        data: { valid: true, user: decoded }
      });
    } catch (error) {
      res.json({
        success: true,
        data: { valid: false }
      });
    }
  }
}

module.exports = new AuthController();
` : `import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { User } from '../models/User.js';
import { redis } from '../config/redis.js';
import { authQueue } from '../queues/authQueue.js';

export class AuthController {
  async register(req, res) {
    try {
      const { name, email, password } = req.body;

      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          error: 'User already exists'
        });
      }

      const user = await User.create({ name, email, password });

      const accessToken = jwt.sign(
        { userId: user.id, service: 'auth' },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN }
      );

      const refreshToken = jwt.sign(
        { userId: user.id, service: 'auth' },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN }
      );

      await redis.set(\`refresh_token:\${user.id}\`, refreshToken, 'EX', 60 * 60 * 24 * 7);

      await authQueue.add('send-welcome-email', {
        userId: user.id,
        email: user.email,
        name: user.name
      });

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: {
          user: {
            id: user.id,
            name: user.name,
            email: user.email
          },
          tokens: {
            accessToken,
            refreshToken
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async login(req, res) {
    try {
      const { email, password } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({
          success: false,
          error: 'Invalid credentials'
        });
      }

      const isMatch = await user.comparePassword(password);
      if (!isMatch) {
        return res.status(400).json({
          success: false,
          error: 'Invalid credentials'
        });
      }

      const accessToken = jwt.sign(
        { userId: user.id, service: 'auth' },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN }
      );

      const refreshToken = jwt.sign(
        { userId: user.id, service: 'auth' },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN }
      );

      await redis.set(\`refresh_token:\${user.id}\`, refreshToken, 'EX', 60 * 60 * 24 * 7);

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user.id,
            name: user.name,
            email: user.email
          },
          tokens: {
            accessToken,
            refreshToken
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return res.status(400).json({
          success: false,
          error: 'Refresh token required'
        });
      }

      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
      
      const storedToken = await redis.get(\`refresh_token:\${decoded.userId}\`);
      if (storedToken !== refreshToken) {
        return res.status(401).json({
          success: false,
          error: 'Invalid refresh token'
        });
      }

      const accessToken = jwt.sign(
        { userId: decoded.userId, service: 'auth' },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN }
      );

      res.json({
        success: true,
        data: { accessToken }
      });
    } catch (error) {
      res.status(401).json({
        success: false,
        error: 'Invalid refresh token'
      });
    }
  }

  async validateToken(req, res) {
    try {
      const { token } = req.body;

      if (!token) {
        return res.status(400).json({
          success: false,
          error: 'Token required'
        });
      }

      const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
      
      res.json({
        success: true,
        data: { valid: true, user: decoded }
      });
    } catch (error) {
      res.json({
        success: true,
        data: { valid: false }
      });
    }
  }
}

export default new AuthController();
`;

    await fs.writeFile(
      path.join(servicePath, `src/controllers/AuthController.${ext}`),
      authController
    );

    // Generate BullMQ queue for auth service
    if (this.config.microservices.messageQueue.includes('bullmq')) {
      const authQueue = isCJS ? `const { Queue } = require('bullmq');
const IORedis = require('ioredis');
const { sendWelcomeEmail } = require('../services/emailService');

const connection = new IORedis(process.env.REDIS_URL, {
  maxRetriesPerRequest: null
});

const authQueue = new Queue('auth', { connection });

// Queue processors
authQueue.process('send-welcome-email', async (job) => {
  const { userId, email, name } = job.data;
  
  try {
    await sendWelcomeEmail({ email, name });
    console.log(\`Welcome email sent to \${email}\`);
  } catch (error) {
    console.error('Failed to send welcome email:', error);
    throw error;
  }
});

authQueue.process('send-password-reset', async (job) => {
  const { email, resetToken } = job.data;
  
  try {
    // Implement password reset email logic
    console.log(\`Password reset email sent to \${email}\`);
  } catch (error) {
    console.error('Failed to send password reset email:', error);
    throw error;
  }
});

module.exports = { authQueue };
` : `import { Queue } from 'bullmq';
import IORedis from 'ioredis';
import { sendWelcomeEmail } from '../services/emailService.js';

const connection = new IORedis(process.env.REDIS_URL, {
  maxRetriesPerRequest: null
});

const authQueue = new Queue('auth', { connection });

authQueue.process('send-welcome-email', async (job) => {
  const { userId, email, name } = job.data;
  
  try {
    await sendWelcomeEmail({ email, name });
    console.log(\`Welcome email sent to \${email}\`);
  } catch (error) {
    console.error('Failed to send welcome email:', error);
    throw error;
  }
});

authQueue.process('send-password-reset', async (job) => {
  const { email, resetToken } = job.data;
  
  try {
    console.log(\`Password reset email sent to \${email}\`);
  } catch (error) {
    console.error('Failed to send password reset email:', error);
    throw error;
  }
});

export { authQueue };
`;

      await fs.writeFile(
        path.join(servicePath, `src/queues/authQueue.${ext}`),
        authQueue
      );
    }
  }

  async generateNotificationService(servicePath) {
    const ext = 'js';
    const isCJS = this.config.moduleType === 'cjs';

    // Notification Controller with BullMQ
    const notificationController = isCJS ? `const { notificationQueue } = require('../queues/notificationQueue');
const { sendEmail } = require('../services/emailService');
const { sendSMS } = require('../services/smsService');

class NotificationController {
  async sendEmail(req, res) {
    try {
      const { to, subject, template, data } = req.body;

      await notificationQueue.add('send-email', {
        to,
        subject,
        template,
        data
      });

      res.json({
        success: true,
        message: 'Email queued for sending'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async sendBulkEmail(req, res) {
    try {
      const { emails, subject, template, data } = req.body;

      const jobs = emails.map(email => ({
        name: 'send-email',
        data: { to: email, subject, template, data }
      }));

      await notificationQueue.addBulk(jobs);

      res.json({
        success: true,
        message: \`\${emails.length} emails queued for sending\`
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getNotificationStatus(req, res) {
    try {
      const { jobId } = req.params;

      const job = await notificationQueue.getJob(jobId);
      
      if (!job) {
        return res.status(404).json({
          success: false,
          error: 'Job not found'
        });
      }

      res.json({
        success: true,
        data: {
          id: job.id,
          status: await job.getState(),
          progress: job.progress,
          result: job.returnvalue
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
}

module.exports = new NotificationController();
` : `import { notificationQueue } from '../queues/notificationQueue.js';
import { sendEmail } from '../services/emailService.js';
import { sendSMS } from '../services/smsService.js';

export class NotificationController {
  async sendEmail(req, res) {
    try {
      const { to, subject, template, data } = req.body;

      await notificationQueue.add('send-email', {
        to,
        subject,
        template,
        data
      });

      res.json({
        success: true,
        message: 'Email queued for sending'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async sendBulkEmail(req, res) {
    try {
      const { emails, subject, template, data } = req.body;

      const jobs = emails.map(email => ({
        name: 'send-email',
        data: { to: email, subject, template, data }
      }));

      await notificationQueue.addBulk(jobs);

      res.json({
        success: true,
        message: \`\${emails.length} emails queued for sending\`
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  async getNotificationStatus(req, res) {
    try {
      const { jobId } = req.params;

      const job = await notificationQueue.getJob(jobId);
      
      if (!job) {
        return res.status(404).json({
          success: false,
          error: 'Job not found'
        });
      }

      res.json({
        success: true,
        data: {
          id: job.id,
          status: await job.getState(),
          progress: job.progress,
          result: job.returnvalue
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
}

export default new NotificationController();
`;

    await fs.writeFile(
      path.join(servicePath, `src/controllers/NotificationController.${ext}`),
      notificationController
    );
  }

  async generateSharedComponents() {
    const sharedPath = path.join(this.projectPath, 'shared');
    
    const sharedDirs = [
      'utils',
      'constants',
      'types',
      'middlewares',
      'validators'
    ];

    for (const dir of sharedDirs) {
      await this.ensureDirectory(path.join(sharedPath, dir));
    }

    // Generate shared utilities
    await this.generateSharedUtils();
    await this.generateSharedConstants();
    await this.generateSharedMiddleware();
  }
  async generateSharedUtils() {
  const sharedPath = path.join(this.projectPath, 'shared');
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  // Response Utility
  const responseUtil = isCJS ? `class ApiResponse {
  constructor(success, data, message = '', error = null) {
    this.success = success;
    this.data = data;
    this.message = message;
    this.error = error;
    this.timestamp = new Date().toISOString();
  }

  static success(data, message = '') {
    return new ApiResponse(true, data, message);
  }

  static error(error, message = '') {
    return new ApiResponse(false, null, message, error);
  }

  static pagination(data, pagination, message = '') {
    return new ApiResponse(true, {
      data,
      pagination
    }, message);
  }
}

class AppError extends Error {
  constructor(message, statusCode, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.status = \`\${statusCode}\`.startsWith('4') ? 'fail' : 'error';

    Error.captureStackTrace(this, this.constructor);
  }
}

// Validation utility
const validateRequest = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      const errorMessage = error.details.map(detail => detail.message).join(', ');
      return res.status(400).json(ApiResponse.error(errorMessage, 'Validation failed'));
    }

    req.body = value;
    next();
  };
};

// Async error handler wrapper
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Password utility
const passwordUtil = {
  validatePassword: (password) => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return {
      isValid: password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar,
      requirements: {
        minLength,
        hasUpperCase,
        hasLowerCase,
        hasNumbers,
        hasSpecialChar
      }
    };
  },

  generateRandomPassword: (length = 12) => {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < length; i++) {
      password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return password;
  }
};

// File utility
const fileUtil = {
  getFileExtension: (filename) => {
    return filename.slice((filename.lastIndexOf('.') - 1 >>> 0) + 2);
  },

  isValidFileType: (filename, allowedTypes) => {
    const extension = this.getFileExtension(filename).toLowerCase();
    return allowedTypes.includes(extension);
  },

  formatFileSize: (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
};

// Date utility
const dateUtil = {
  formatDate: (date, format = 'YYYY-MM-DD') => {
    const d = new Date(date);
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const hours = String(d.getHours()).padStart(2, '0');
    const minutes = String(d.getMinutes()).padStart(2, '0');
    const seconds = String(d.getSeconds()).padStart(2, '0');

    return format
      .replace('YYYY', year)
      .replace('MM', month)
      .replace('DD', day)
      .replace('HH', hours)
      .replace('mm', minutes)
      .replace('ss', seconds);
  },

  addDays: (date, days) => {
    const result = new Date(date);
    result.setDate(result.getDate() + days);
    return result;
  },

  isExpired: (date) => {
    return new Date(date) < new Date();
  }
};

// String utility
const stringUtil = {
  capitalize: (str) => {
    return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
  },

  generateSlug: (str) => {
    return str
      .toLowerCase()
      .trim()
      .replace(/[^\\w\\s-]/g, '')
      .replace(/[\\s_-]+/g, '-')
      .replace(/^-+|-+$/g, '');
  },

  truncate: (str, length, suffix = '...') => {
    if (str.length <= length) return str;
    return str.substring(0, length - suffix.length) + suffix;
  },

  maskEmail: (email) => {
    const [local, domain] = email.split('@');
    const maskedLocal = local.substring(0, 2) + '*'.repeat(local.length - 2);
    return \`\${maskedLocal}@\${domain}\`;
  }
};

// Cache utility
const cacheUtil = {
  generateKey: (prefix, ...args) => {
    return \`\${prefix}:\${args.join(':')}\`;
  },

  parseKey: (key) => {
    return key.split(':');
  }
};

module.exports = {
  ApiResponse,
  AppError,
  validateRequest,
  asyncHandler,
  passwordUtil,
  fileUtil,
  dateUtil,
  stringUtil,
  cacheUtil
};
` : `export class ApiResponse {
  constructor(success, data, message = '', error = null) {
    this.success = success;
    this.data = data;
    this.message = message;
    this.error = error;
    this.timestamp = new Date().toISOString();
  }

  static success(data, message = '') {
    return new ApiResponse(true, data, message);
  }

  static error(error, message = '') {
    return new ApiResponse(false, null, message, error);
  }

  static pagination(data, pagination, message = '') {
    return new ApiResponse(true, {
      data,
      pagination
    }, message);
  }
}

export class AppError extends Error {
  constructor(message, statusCode, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.status = \`\${statusCode}\`.startsWith('4') ? 'fail' : 'error';

    Error.captureStackTrace(this, this.constructor);
  }
}

export const validateRequest = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      const errorMessage = error.details.map(detail => detail.message).join(', ');
      return res.status(400).json(ApiResponse.error(errorMessage, 'Validation failed'));
    }

    req.body = value;
    next();
  };
};

export const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

export const passwordUtil = {
  validatePassword: (password) => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return {
      isValid: password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar,
      requirements: {
        minLength,
        hasUpperCase,
        hasLowerCase,
        hasNumbers,
        hasSpecialChar
      }
    };
  },

  generateRandomPassword: (length = 12) => {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < length; i++) {
      password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return password;
  }
};

export const fileUtil = {
  getFileExtension: (filename) => {
    return filename.slice((filename.lastIndexOf('.') - 1 >>> 0) + 2);
  },

  isValidFileType: (filename, allowedTypes) => {
    const extension = this.getFileExtension(filename).toLowerCase();
    return allowedTypes.includes(extension);
  },

  formatFileSize: (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
};

export const dateUtil = {
  formatDate: (date, format = 'YYYY-MM-DD') => {
    const d = new Date(date);
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const hours = String(d.getHours()).padStart(2, '0');
    const minutes = String(d.getMinutes()).padStart(2, '0');
    const seconds = String(d.getSeconds()).padStart(2, '0');

    return format
      .replace('YYYY', year)
      .replace('MM', month)
      .replace('DD', day)
      .replace('HH', hours)
      .replace('mm', minutes)
      .replace('ss', seconds);
  },

  addDays: (date, days) => {
    const result = new Date(date);
    result.setDate(result.getDate() + days);
    return result;
  },

  isExpired: (date) => {
    return new Date(date) < new Date();
  }
};

export const stringUtil = {
  capitalize: (str) => {
    return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
  },

  generateSlug: (str) => {
    return str
      .toLowerCase()
      .trim()
      .replace(/[^\\w\\s-]/g, '')
      .replace(/[\\s_-]+/g, '-')
      .replace(/^-+|-+$/g, '');
  },

  truncate: (str, length, suffix = '...') => {
    if (str.length <= length) return str;
    return str.substring(0, length - suffix.length) + suffix;
  },

  maskEmail: (email) => {
    const [local, domain] = email.split('@');
    const maskedLocal = local.substring(0, 2) + '*'.repeat(local.length - 2);
    return \`\${maskedLocal}@\${domain}\`;
  }
};

export const cacheUtil = {
  generateKey: (prefix, ...args) => {
    return \`\${prefix}:\${args.join(':')}\`;
  },

  parseKey: (key) => {
    return key.split(':');
  }
};
`;

  await fs.writeFile(
    path.join(sharedPath, `utils/index.${ext}`),
    responseUtil
  );

  // Logger Utility
  const loggerUtil = isCJS ? `const winston = require('winston');
const path = require('path');

const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

const createLogger = (serviceName) => {
  const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    defaultMeta: { service: serviceName },
    format: logFormat,
    transports: [
      new winston.transports.File({ 
        filename: path.join('logs', 'error.log'), 
        level: 'error' 
      }),
      new winston.transports.File({ 
        filename: path.join('logs', 'combined.log') 
      })
    ]
  });

  if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }));
  }

  return logger;
};

const requestLogger = (serviceName) => {
  const logger = createLogger(serviceName);

  return (req, res, next) => {
    const start = Date.now();

    res.on('finish', () => {
      const duration = Date.now() - start;
      logger.info({
        message: 'HTTP request',
        method: req.method,
        url: req.url,
        status: res.statusCode,
        duration: \`\${duration}ms\`,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
    });

    next();
  };
};

module.exports = {
  createLogger,
  requestLogger
};
` : `import winston from 'winston';
import path from 'path';

const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

export const createLogger = (serviceName) => {
  const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    defaultMeta: { service: serviceName },
    format: logFormat,
    transports: [
      new winston.transports.File({ 
        filename: path.join('logs', 'error.log'), 
        level: 'error' 
      }),
      new winston.transports.File({ 
        filename: path.join('logs', 'combined.log') 
      })
    ]
  });

  if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }));
  }

  return logger;
};

export const requestLogger = (serviceName) => {
  const logger = createLogger(serviceName);

  return (req, res, next) => {
    const start = Date.now();

    res.on('finish', () => {
      const duration = Date.now() - start;
      logger.info({
        message: 'HTTP request',
        method: req.method,
        url: req.url,
        status: res.statusCode,
        duration: \`\${duration}ms\`,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
    });

    next();
  };
};
`;

  await fs.writeFile(
    path.join(sharedPath, `utils/logger.${ext}`),
    loggerUtil
  );
}

async generateSharedConstants() {
  const sharedPath = path.join(this.projectPath, 'shared');
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  // HTTP Status Codes
  const httpConstants = isCJS ? `const HTTP_STATUS = {
  // Success
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,

  // Client errors
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,

  // Server errors
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504
};

const ERROR_CODES = {
  // Authentication errors
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_INVALID: 'TOKEN_INVALID',
  ACCESS_DENIED: 'ACCESS_DENIED',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',

  // Validation errors
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  REQUIRED_FIELD: 'REQUIRED_FIELD',
  INVALID_EMAIL: 'INVALID_EMAIL',
  INVALID_PASSWORD: 'INVALID_PASSWORD',

  // Resource errors
  RESOURCE_NOT_FOUND: 'RESOURCE_NOT_FOUND',
  RESOURCE_ALREADY_EXISTS: 'RESOURCE_ALREADY_EXISTS',
  RESOURCE_CONFLICT: 'RESOURCE_CONFLICT',

  // System errors
  DATABASE_ERROR: 'DATABASE_ERROR',
  EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR',
  NETWORK_ERROR: 'NETWORK_ERROR'
};

const USER_ROLES = {
  USER: 'user',
  ADMIN: 'admin',
  MODERATOR: 'moderator',
  SUPER_ADMIN: 'super_admin'
};

const PERMISSIONS = {
  // User permissions
  USER_READ: 'user:read',
  USER_WRITE: 'user:write',
  USER_DELETE: 'user:delete',

  // Content permissions
  CONTENT_READ: 'content:read',
  CONTENT_WRITE: 'content:write',
  CONTENT_DELETE: 'content:delete',

  // System permissions
  SYSTEM_READ: 'system:read',
  SYSTEM_WRITE: 'system:write',
  SYSTEM_DELETE: 'system:delete'
};

const ROLE_PERMISSIONS = {
  [USER_ROLES.USER]: [
    PERMISSIONS.USER_READ,
    PERMISSIONS.CONTENT_READ,
    PERMISSIONS.CONTENT_WRITE
  ],
  [USER_ROLES.MODERATOR]: [
    ...ROLE_PERMISSIONS[USER_ROLES.USER],
    PERMISSIONS.USER_WRITE,
    PERMISSIONS.CONTENT_DELETE
  ],
  [USER_ROLES.ADMIN]: [
    ...ROLE_PERMISSIONS[USER_ROLES.MODERATOR],
    PERMISSIONS.USER_DELETE,
    PERMISSIONS.SYSTEM_READ
  ],
  [USER_ROLES.SUPER_ADMIN]: Object.values(PERMISSIONS)
};

const FILE_TYPES = {
  IMAGE: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'],
  DOCUMENT: ['pdf', 'doc', 'docx', 'txt', 'rtf'],
  SPREADSHEET: ['xls', 'xlsx', 'csv'],
  PRESENTATION: ['ppt', 'pptx'],
  ARCHIVE: ['zip', 'rar', '7z', 'tar', 'gz'],
  AUDIO: ['mp3', 'wav', 'ogg', 'm4a'],
  VIDEO: ['mp4', 'avi', 'mov', 'wmv', 'flv', 'webm']
};

const MAX_FILE_SIZES = {
  IMAGE: 5 * 1024 * 1024, // 5MB
  DOCUMENT: 10 * 1024 * 1024, // 10MB
  AUDIO: 20 * 1024 * 1024, // 20MB
  VIDEO: 100 * 1024 * 1024, // 100MB
  DEFAULT: 5 * 1024 * 1024 // 5MB
};

const EVENT_TYPES = {
  USER_SIGNUP: 'user_signup',
  USER_LOGIN: 'user_login',
  USER_LOGOUT: 'user_logout',
  USER_PROFILE_UPDATE: 'user_profile_update',
  PAYMENT_SUCCESS: 'payment_success',
  PAYMENT_FAILED: 'payment_failed',
  FILE_UPLOAD: 'file_upload',
  FILE_DOWNLOAD: 'file_download',
  NOTIFICATION_SENT: 'notification_sent'
};

const NOTIFICATION_TYPES = {
  EMAIL: 'email',
  SMS: 'sms',
  PUSH: 'push',
  IN_APP: 'in_app'
};

const PAYMENT_STATUS = {
  PENDING: 'pending',
  COMPLETED: 'completed',
  FAILED: 'failed',
  REFUNDED: 'refunded',
  CANCELLED: 'cancelled'
};

const CURRENCIES = {
  USD: 'usd',
  EUR: 'eur',
  GBP: 'gbp',
  JPY: 'jpy',
  CAD: 'cad',
  AUD: 'aud'
};

module.exports = {
  HTTP_STATUS,
  ERROR_CODES,
  USER_ROLES,
  PERMISSIONS,
  ROLE_PERMISSIONS,
  FILE_TYPES,
  MAX_FILE_SIZES,
  EVENT_TYPES,
  NOTIFICATION_TYPES,
  PAYMENT_STATUS,
  CURRENCIES
};
` : `export const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504
};

export const ERROR_CODES = {
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_INVALID: 'TOKEN_INVALID',
  ACCESS_DENIED: 'ACCESS_DENIED',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  REQUIRED_FIELD: 'REQUIRED_FIELD',
  INVALID_EMAIL: 'INVALID_EMAIL',
  INVALID_PASSWORD: 'INVALID_PASSWORD',
  RESOURCE_NOT_FOUND: 'RESOURCE_NOT_FOUND',
  RESOURCE_ALREADY_EXISTS: 'RESOURCE_ALREADY_EXISTS',
  RESOURCE_CONFLICT: 'RESOURCE_CONFLICT',
  DATABASE_ERROR: 'DATABASE_ERROR',
  EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR',
  NETWORK_ERROR: 'NETWORK_ERROR'
};

export const USER_ROLES = {
  USER: 'user',
  ADMIN: 'admin',
  MODERATOR: 'moderator',
  SUPER_ADMIN: 'super_admin'
};

export const PERMISSIONS = {
  USER_READ: 'user:read',
  USER_WRITE: 'user:write',
  USER_DELETE: 'user:delete',
  CONTENT_READ: 'content:read',
  CONTENT_WRITE: 'content:write',
  CONTENT_DELETE: 'content:delete',
  SYSTEM_READ: 'system:read',
  SYSTEM_WRITE: 'system:write',
  SYSTEM_DELETE: 'system:delete'
};

export const ROLE_PERMISSIONS = {
  [USER_ROLES.USER]: [
    PERMISSIONS.USER_READ,
    PERMISSIONS.CONTENT_READ,
    PERMISSIONS.CONTENT_WRITE
  ],
  [USER_ROLES.MODERATOR]: [
    ...ROLE_PERMISSIONS[USER_ROLES.USER],
    PERMISSIONS.USER_WRITE,
    PERMISSIONS.CONTENT_DELETE
  ],
  [USER_ROLES.ADMIN]: [
    ...ROLE_PERMISSIONS[USER_ROLES.MODERATOR],
    PERMISSIONS.USER_DELETE,
    PERMISSIONS.SYSTEM_READ
  ],
  [USER_ROLES.SUPER_ADMIN]: Object.values(PERMISSIONS)
};

export const FILE_TYPES = {
  IMAGE: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'],
  DOCUMENT: ['pdf', 'doc', 'docx', 'txt', 'rtf'],
  SPREADSHEET: ['xls', 'xlsx', 'csv'],
  PRESENTATION: ['ppt', 'pptx'],
  ARCHIVE: ['zip', 'rar', '7z', 'tar', 'gz'],
  AUDIO: ['mp3', 'wav', 'ogg', 'm4a'],
  VIDEO: ['mp4', 'avi', 'mov', 'wmv', 'flv', 'webm']
};

export const MAX_FILE_SIZES = {
  IMAGE: 5 * 1024 * 1024,
  DOCUMENT: 10 * 1024 * 1024,
  AUDIO: 20 * 1024 * 1024,
  VIDEO: 100 * 1024 * 1024,
  DEFAULT: 5 * 1024 * 1024
};

export const EVENT_TYPES = {
  USER_SIGNUP: 'user_signup',
  USER_LOGIN: 'user_login',
  USER_LOGOUT: 'user_logout',
  USER_PROFILE_UPDATE: 'user_profile_update',
  PAYMENT_SUCCESS: 'payment_success',
  PAYMENT_FAILED: 'payment_failed',
  FILE_UPLOAD: 'file_upload',
  FILE_DOWNLOAD: 'file_download',
  NOTIFICATION_SENT: 'notification_sent'
};

export const NOTIFICATION_TYPES = {
  EMAIL: 'email',
  SMS: 'sms',
  PUSH: 'push',
  IN_APP: 'in_app'
};

export const PAYMENT_STATUS = {
  PENDING: 'pending',
  COMPLETED: 'completed',
  FAILED: 'failed',
  REFUNDED: 'refunded',
  CANCELLED: 'cancelled'
};

export const CURRENCIES = {
  USD: 'usd',
  EUR: 'eur',
  GBP: 'gbp',
  JPY: 'jpy',
  CAD: 'cad',
  AUD: 'aud'
};
`;

  await fs.writeFile(
    path.join(sharedPath, `constants/index.${ext}`),
    httpConstants
  );

  // Service Constants
  const serviceConstants = isCJS ? `const SERVICE_NAMES = {
  AUTH: 'auth',
  USER: 'user',
  NOTIFICATION: 'notification',
  FILE: 'file',
  PAYMENT: 'payment',
  ANALYTICS: 'analytics',
  API_GATEWAY: 'api-gateway'
};

const SERVICE_PORTS = {
  [SERVICE_NAMES.AUTH]: 3001,
  [SERVICE_NAMES.USER]: 3002,
  [SERVICE_NAMES.NOTIFICATION]: 3003,
  [SERVICE_NAMES.FILE]: 3004,
  [SERVICE_NAMES.PAYMENT]: 3005,
  [SERVICE_NAMES.ANALYTICS]: 3006,
  [SERVICE_NAMES.API_GATEWAY]: 3000
};

const SERVICE_URLS = {
  [SERVICE_NAMES.AUTH]: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.AUTH]}\`,
  [SERVICE_NAMES.USER]: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.USER]}\`,
  [SERVICE_NAMES.NOTIFICATION]: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.NOTIFICATION]}\`,
  [SERVICE_NAMES.FILE]: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.FILE]}\`,
  [SERVICE_NAMES.PAYMENT]: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.PAYMENT]}\`,
  [SERVICE_NAMES.ANALYTICS]: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.ANALYTICS]}\`
};

const QUEUE_NAMES = {
  AUTH: 'auth',
  NOTIFICATION: 'notification',
  PAYMENT: 'payment',
  ANALYTICS: 'analytics'
};

const JWT_CONFIG = {
  ACCESS_TOKEN_EXPIRY: '15m',
  REFRESH_TOKEN_EXPIRY: '7d',
  ISSUER: 'microservices-app'
};

const REDIS_CONFIG = {
  DEFAULT_EXPIRY: 3600, // 1 hour in seconds
  SHORT_EXPIRY: 300,    // 5 minutes
  LONG_EXPIRY: 86400    // 24 hours
};

const RATE_LIMIT_CONFIG = {
  WINDOW_MS: 15 * 60 * 1000, // 15 minutes
  MAX_REQUESTS: 100, // Limit each IP to 100 requests per windowMs
  MESSAGE: 'Too many requests from this IP, please try again later.'
};

const DATABASE_CONFIG = {
  RECONNECT_INTERVAL: 5000, // 5 seconds
  MAX_RECONNECT_ATTEMPTS: 10
};

module.exports = {
  SERVICE_NAMES,
  SERVICE_PORTS,
  SERVICE_URLS,
  QUEUE_NAMES,
  JWT_CONFIG,
  REDIS_CONFIG,
  RATE_LIMIT_CONFIG,
  DATABASE_CONFIG
};
` : `export const SERVICE_NAMES = {
  AUTH: 'auth',
  USER: 'user',
  NOTIFICATION: 'notification',
  FILE: 'file',
  PAYMENT: 'payment',
  ANALYTICS: 'analytics',
  API_GATEWAY: 'api-gateway'
};

export const SERVICE_PORTS = {
  [SERVICE_NAMES.AUTH]: 3001,
  [SERVICE_NAMES.USER]: 3002,
  [SERVICE_NAMES.NOTIFICATION]: 3003,
  [SERVICE_NAMES.FILE]: 3004,
  [SERVICE_NAMES.PAYMENT]: 3005,
  [SERVICE_NAMES.ANALYTICS]: 3006,
  [SERVICE_NAMES.API_GATEWAY]: 3000
};

export const SERVICE_URLS = {
  [SERVICE_NAMES.AUTH]: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.AUTH]}\`,
  [SERVICE_NAMES.USER]: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.USER]}\`,
  [SERVICE_NAMES.NOTIFICATION]: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.NOTIFICATION]}\`,
  [SERVICE_NAMES.FILE]: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.FILE]}\`,
  [SERVICE_NAMES.PAYMENT]: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.PAYMENT]}\`,
  [SERVICE_NAMES.ANALYTICS]: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.ANALYTICS]}\`
};

export const QUEUE_NAMES = {
  AUTH: 'auth',
  NOTIFICATION: 'notification',
  PAYMENT: 'payment',
  ANALYTICS: 'analytics'
};

export const JWT_CONFIG = {
  ACCESS_TOKEN_EXPIRY: '15m',
  REFRESH_TOKEN_EXPIRY: '7d',
  ISSUER: 'microservices-app'
};

export const REDIS_CONFIG = {
  DEFAULT_EXPIRY: 3600,
  SHORT_EXPIRY: 300,
  LONG_EXPIRY: 86400
};

export const RATE_LIMIT_CONFIG = {
  WINDOW_MS: 15 * 60 * 1000,
  MAX_REQUESTS: 100,
  MESSAGE: 'Too many requests from this IP, please try again later.'
};

export const DATABASE_CONFIG = {
  RECONNECT_INTERVAL: 5000,
  MAX_RECONNECT_ATTEMPTS: 10
};
`;

  await fs.writeFile(
    path.join(sharedPath, `constants/services.${ext}`),
    serviceConstants
  );
}

async generateSharedMiddleware() {
  const sharedPath = path.join(this.projectPath, 'shared');
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  // Authentication Middleware
  const authMiddleware = isCJS ? `const jwt = require('jsonwebtoken');
const { AppError, asyncHandler } = require('../utils');
const { HTTP_STATUS, ERROR_CODES } = require('../constants');
const { redis } = require('../config/redis');

const authenticateToken = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    throw new AppError('Access token required', HTTP_STATUS.UNAUTHORIZED);
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    
    // Check if token is blacklisted (for logout functionality)
    const isBlacklisted = await redis.get(\`blacklisted_token:\${token}\`);
    if (isBlacklisted) {
      throw new AppError('Token has been invalidated', HTTP_STATUS.UNAUTHORIZED);
    }

    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new AppError('Token expired', HTTP_STATUS.UNAUTHORIZED, ERROR_CODES.TOKEN_EXPIRED);
    } else if (error.name === 'JsonWebTokenError') {
      throw new AppError('Invalid token', HTTP_STATUS.UNAUTHORIZED, ERROR_CODES.TOKEN_INVALID);
    } else {
      throw new AppError('Authentication failed', HTTP_STATUS.UNAUTHORIZED);
    }
  }
});

const optionalAuth = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
      const isBlacklisted = await redis.get(\`blacklisted_token:\${token}\`);
      
      if (!isBlacklisted) {
        req.user = decoded;
      }
    } catch (error) {
      // Silently fail for optional auth
    }
  }

  next();
});

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      throw new AppError('Authentication required', HTTP_STATUS.UNAUTHORIZED);
    }

    if (!roles.includes(req.user.role)) {
      throw new AppError('Insufficient permissions', HTTP_STATUS.FORBIDDEN, ERROR_CODES.ACCESS_DENIED);
    }

    next();
  };
};

const requireService = (serviceName) => {
  return (req, res, next) => {
    if (!req.user || req.user.service !== serviceName) {
      throw new AppError(\`Access denied for \${serviceName} service\`, HTTP_STATUS.FORBIDDEN);
    }
    next();
  };
};

// Service-to-service authentication
const serviceAuth = asyncHandler(async (req, res, next) => {
  const serviceToken = req.headers['x-service-token'];

  if (!serviceToken) {
    throw new AppError('Service token required', HTTP_STATUS.UNAUTHORIZED);
  }

  try {
    const decoded = jwt.verify(serviceToken, process.env.JWT_SERVICE_SECRET);
    
    if (decoded.type !== 'service') {
      throw new AppError('Invalid service token', HTTP_STATUS.UNAUTHORIZED);
    }

    req.service = decoded;
    next();
  } catch (error) {
    throw new AppError('Service authentication failed', HTTP_STATUS.UNAUTHORIZED);
  }
});

// Generate service token (for inter-service communication)
const generateServiceToken = (serviceName) => {
  return jwt.sign(
    { 
      service: serviceName, 
      type: 'service',
      timestamp: Date.now()
    },
    process.env.JWT_SERVICE_SECRET,
    { expiresIn: '1h' }
  );
};

module.exports = {
  authenticateToken,
  optionalAuth,
  authorize,
  requireService,
  serviceAuth,
  generateServiceToken
};
` : `import jwt from 'jsonwebtoken';
import { AppError, asyncHandler } from '../utils/index.js';
import { HTTP_STATUS, ERROR_CODES } from '../constants/index.js';
import { redis } from '../config/redis.js';

export const authenticateToken = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    throw new AppError('Access token required', HTTP_STATUS.UNAUTHORIZED);
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    
    const isBlacklisted = await redis.get(\`blacklisted_token:\${token}\`);
    if (isBlacklisted) {
      throw new AppError('Token has been invalidated', HTTP_STATUS.UNAUTHORIZED);
    }

    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new AppError('Token expired', HTTP_STATUS.UNAUTHORIZED, ERROR_CODES.TOKEN_EXPIRED);
    } else if (error.name === 'JsonWebTokenError') {
      throw new AppError('Invalid token', HTTP_STATUS.UNAUTHORIZED, ERROR_CODES.TOKEN_INVALID);
    } else {
      throw new AppError('Authentication failed', HTTP_STATUS.UNAUTHORIZED);
    }
  }
});

export const optionalAuth = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
      const isBlacklisted = await redis.get(\`blacklisted_token:\${token}\`);
      
      if (!isBlacklisted) {
        req.user = decoded;
      }
    } catch (error) {
      // Silently fail for optional auth
    }
  }

  next();
});

export const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      throw new AppError('Authentication required', HTTP_STATUS.UNAUTHORIZED);
    }

    if (!roles.includes(req.user.role)) {
      throw new AppError('Insufficient permissions', HTTP_STATUS.FORBIDDEN, ERROR_CODES.ACCESS_DENIED);
    }

    next();
  };
};

export const requireService = (serviceName) => {
  return (req, res, next) => {
    if (!req.user || req.user.service !== serviceName) {
      throw new AppError(\`Access denied for \${serviceName} service\`, HTTP_STATUS.FORBIDDEN);
    }
    next();
  };
};

export const serviceAuth = asyncHandler(async (req, res, next) => {
  const serviceToken = req.headers['x-service-token'];

  if (!serviceToken) {
    throw new AppError('Service token required', HTTP_STATUS.UNAUTHORIZED);
  }

  try {
    const decoded = jwt.verify(serviceToken, process.env.JWT_SERVICE_SECRET);
    
    if (decoded.type !== 'service') {
      throw new AppError('Invalid service token', HTTP_STATUS.UNAUTHORIZED);
    }

    req.service = decoded;
    next();
  } catch (error) {
    throw new AppError('Service authentication failed', HTTP_STATUS.UNAUTHORIZED);
  }
});

export const generateServiceToken = (serviceName) => {
  return jwt.sign(
    { 
      service: serviceName, 
      type: 'service',
      timestamp: Date.now()
    },
    process.env.JWT_SERVICE_SECRET,
    { expiresIn: '1h' }
  );
};
`;

  await fs.writeFile(
    path.join(sharedPath, `middlewares/auth.${ext}`),
    authMiddleware
  );

  // Error Handling Middleware
  const errorMiddleware = isCJS ? `const { AppError } = require('../utils');
const { HTTP_STATUS } = require('../constants');
const { createLogger } = require('../utils/logger');

const logger = createLogger('error-handler');

const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  // Log error
  logger.error({
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = 'Resource not found';
    error = new AppError(message, HTTP_STATUS.NOT_FOUND);
  }

  // Mongoose duplicate key
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const value = err.keyValue[field];
    const message = \`Duplicate field value: \${field} = \${value}. Please use another value.\`;
    error = new AppError(message, HTTP_STATUS.CONFLICT);
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(val => val.message);
    const message = \`Invalid input data: \${messages.join(', ')}\`;
    error = new AppError(message, HTTP_STATUS.UNPROCESSABLE_ENTITY);
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    const message = 'Invalid token';
    error = new AppError(message, HTTP_STATUS.UNAUTHORIZED);
  }

  if (err.name === 'TokenExpiredError') {
    const message = 'Token expired';
    error = new AppError(message, HTTP_STATUS.UNAUTHORIZED);
  }

  res.status(error.statusCode || HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: error.message || 'Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
  });
};

const notFound = (req, res, next) => {
  const error = new AppError(\`Not found - \${req.originalUrl}\`, HTTP_STATUS.NOT_FOUND);
  next(error);
};

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = {
  errorHandler,
  notFound,
  asyncHandler
};
` : `import { AppError } from '../utils/index.js';
import { HTTP_STATUS } from '../constants/index.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('error-handler');

export const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  logger.error({
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  if (err.name === 'CastError') {
    const message = 'Resource not found';
    error = new AppError(message, HTTP_STATUS.NOT_FOUND);
  }

  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const value = err.keyValue[field];
    const message = \`Duplicate field value: \${field} = \${value}. Please use another value.\`;
    error = new AppError(message, HTTP_STATUS.CONFLICT);
  }

  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(val => val.message);
    const message = \`Invalid input data: \${messages.join(', ')}\`;
    error = new AppError(message, HTTP_STATUS.UNPROCESSABLE_ENTITY);
  }

  if (err.name === 'JsonWebTokenError') {
    const message = 'Invalid token';
    error = new AppError(message, HTTP_STATUS.UNAUTHORIZED);
  }

  if (err.name === 'TokenExpiredError') {
    const message = 'Token expired';
    error = new AppError(message, HTTP_STATUS.UNAUTHORIZED);
  }

  res.status(error.statusCode || HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: error.message || 'Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
  });
};

export const notFound = (req, res, next) => {
  const error = new AppError(\`Not found - \${req.originalUrl}\`, HTTP_STATUS.NOT_FOUND);
  next(error);
};

export const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};
`;

  await fs.writeFile(
    path.join(sharedPath, `middlewares/error.${ext}`),
    errorMiddleware
  );

  // Validation Middleware
  const validationMiddleware = isCJS ? `const Joi = require('joi');
const { HTTP_STATUS } = require('../constants');
const { ApiResponse } = require('../utils');

// Common validation schemas
const commonSchemas = {
  objectId: Joi.string().hex().length(24).messages({
    'string.hex': 'Invalid ID format',
    'string.length': 'ID must be 24 characters long'
  }),
  
  email: Joi.string().email().lowercase().trim().messages({
    'string.email': 'Please provide a valid email address'
  }),
  
  password: Joi.string().min(6).max(128).messages({
    'string.min': 'Password must be at least 6 characters long',
    'string.max': 'Password cannot exceed 128 characters'
  }),
  
  phone: Joi.string().pattern(/^[\\+]?[1-9][\\d]{0,15}$/).messages({
    'string.pattern.base': 'Please provide a valid phone number'
  }),
  
  pagination: {
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(10),
    sort: Joi.string().default('-createdAt'),
    search: Joi.string().trim().max(100)
  }
};

// Validation middleware factory
const validate = (schema, source = 'body') => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[source], {
      abortEarly: false,
      stripUnknown: true,
      allowUnknown: true
    });

    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        type: detail.type
      }));

      return res.status(HTTP_STATUS.UNPROCESSABLE_ENTITY).json(
        ApiResponse.error('Validation failed', 'VALIDATION_ERROR', errors)
      );
    }

    req[source] = value;
    next();
  };
};

// Specific validation schemas
const authSchemas = {
  register: Joi.object({
    name: Joi.string().min(2).max(100).required().trim(),
    email: commonSchemas.email.required(),
    password: commonSchemas.password.required(),
    phone: commonSchemas.phone.optional()
  }),
  
  login: Joi.object({
    email: commonSchemas.email.required(),
    password: Joi.string().required()
  }),
  
  refreshToken: Joi.object({
    refreshToken: Joi.string().required()
  }),
  
  changePassword: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: commonSchemas.password.required()
  })
};

const userSchemas = {
  updateProfile: Joi.object({
    name: Joi.string().min(2).max(100).trim(),
    email: commonSchemas.email,
    phone: commonSchemas.phone,
    avatar: Joi.string().uri().optional()
  }),
  
  updatePreferences: Joi.object({
    notifications: Joi.object({
      email: Joi.boolean(),
      push: Joi.boolean(),
      sms: Joi.boolean()
    }),
    language: Joi.string().valid('en', 'es', 'fr', 'de'),
    timezone: Joi.string()
  })
};

const fileSchemas = {
  upload: Joi.object({
    metadata: Joi.object().optional()
  }),
  
  updateFile: Joi.object({
    filename: Joi.string().min(1).max(255).trim(),
    isPublic: Joi.boolean()
  })
};

const paymentSchemas = {
  createPayment: Joi.object({
    amount: Joi.number().positive().precision(2).required(),
    currency: Joi.string().valid('usd', 'eur', 'gbp').default('usd'),
    description: Joi.string().max(255).trim(),
    metadata: Joi.object().optional()
  }),
  
  refundPayment: Joi.object({
    reason: Joi.string().max(255).trim().optional()
  })
};

const analyticsSchemas = {
  trackEvent: Joi.object({
    eventType: Joi.string().required().max(100),
    eventData: Joi.object().optional(),
    userId: commonSchemas.objectId.optional(),
    sessionId: Joi.string().max(100).optional()
  }),
  
  getStats: Joi.object({
    period: Joi.string().valid('1d', '7d', '30d', '90d').default('7d')
  }),
  
  exportData: Joi.object({
    startDate: Joi.date().optional(),
    endDate: Joi.date().optional(),
    format: Joi.string().valid('json', 'csv').default('json')
  })
};

module.exports = {
  validate,
  commonSchemas,
  authSchemas,
  userSchemas,
  fileSchemas,
  paymentSchemas,
  analyticsSchemas
};
` : `import Joi from 'joi';
import { HTTP_STATUS } from '../constants/index.js';
import { ApiResponse } from '../utils/index.js';

export const commonSchemas = {
  objectId: Joi.string().hex().length(24).messages({
    'string.hex': 'Invalid ID format',
    'string.length': 'ID must be 24 characters long'
  }),
  
  email: Joi.string().email().lowercase().trim().messages({
    'string.email': 'Please provide a valid email address'
  }),
  
  password: Joi.string().min(6).max(128).messages({
    'string.min': 'Password must be at least 6 characters long',
    'string.max': 'Password cannot exceed 128 characters'
  }),
  
  phone: Joi.string().pattern(/^[\\+]?[1-9][\\d]{0,15}$/).messages({
    'string.pattern.base': 'Please provide a valid phone number'
  }),
  
  pagination: {
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(10),
    sort: Joi.string().default('-createdAt'),
    search: Joi.string().trim().max(100)
  }
};

export const validate = (schema, source = 'body') => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[source], {
      abortEarly: false,
      stripUnknown: true,
      allowUnknown: true
    });

    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        type: detail.type
      }));

      return res.status(HTTP_STATUS.UNPROCESSABLE_ENTITY).json(
        ApiResponse.error('Validation failed', 'VALIDATION_ERROR', errors)
      );
    }

    req[source] = value;
    next();
  };
};

export const authSchemas = {
  register: Joi.object({
    name: Joi.string().min(2).max(100).required().trim(),
    email: commonSchemas.email.required(),
    password: commonSchemas.password.required(),
    phone: commonSchemas.phone.optional()
  }),
  
  login: Joi.object({
    email: commonSchemas.email.required(),
    password: Joi.string().required()
  }),
  
  refreshToken: Joi.object({
    refreshToken: Joi.string().required()
  }),
  
  changePassword: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: commonSchemas.password.required()
  })
};

export const userSchemas = {
  updateProfile: Joi.object({
    name: Joi.string().min(2).max(100).trim(),
    email: commonSchemas.email,
    phone: commonSchemas.phone,
    avatar: Joi.string().uri().optional()
  }),
  
  updatePreferences: Joi.object({
    notifications: Joi.object({
      email: Joi.boolean(),
      push: Joi.boolean(),
      sms: Joi.boolean()
    }),
    language: Joi.string().valid('en', 'es', 'fr', 'de'),
    timezone: Joi.string()
  })
};

export const fileSchemas = {
  upload: Joi.object({
    metadata: Joi.object().optional()
  }),
  
  updateFile: Joi.object({
    filename: Joi.string().min(1).max(255).trim(),
    isPublic: Joi.boolean()
  })
};

export const paymentSchemas = {
  createPayment: Joi.object({
    amount: Joi.number().positive().precision(2).required(),
    currency: Joi.string().valid('usd', 'eur', 'gbp').default('usd'),
    description: Joi.string().max(255).trim(),
    metadata: Joi.object().optional()
  }),
  
  refundPayment: Joi.object({
    reason: Joi.string().max(255).trim().optional()
  })
};

export const analyticsSchemas = {
  trackEvent: Joi.object({
    eventType: Joi.string().required().max(100),
    eventData: Joi.object().optional(),
    userId: commonSchemas.objectId.optional(),
    sessionId: Joi.string().max(100).optional()
  }),
  
  getStats: Joi.object({
    period: Joi.string().valid('1d', '7d', '30d', '90d').default('7d')
  }),
  
  exportData: Joi.object({
    startDate: Joi.date().optional(),
    endDate: Joi.date().optional(),
    format: Joi.string().valid('json', 'csv').default('json')
  })
};
`;

  await fs.writeFile(
    path.join(sharedPath, `middlewares/validation.${ext}`),
    validationMiddleware
  );
}
  async generateApiGateway() {
    const gatewayPath = path.join(this.projectPath, 'api-gateway');
    
    const gatewayDirs = [
      'src/routes',
      'src/middlewares',
      'src/services',
      'src/utils'
    ];

    for (const dir of gatewayDirs) {
      await this.ensureDirectory(path.join(gatewayPath, dir));
    }

    // Generate API Gateway files
    await this.generateGatewayPackageJson();
    await this.generateGatewayServer();
    await this.generateGatewayRoutes();
  }

  async generateGatewayPackageJson() {
  const gatewayPath = path.join(this.projectPath, 'api-gateway');
  const ext = this.config.moduleType === 'cjs' ? 'cjs' : 'js';
  const isCJS = this.config.moduleType === 'cjs';
  
  const packageJson = {
    name: 'api-gateway',
    version: '1.0.0',
    description: 'API Gateway for microservices architecture',
    main: `src/server.${ext}`,
    type: isCJS ? 'commonjs' : 'module',
    scripts: {
      start: `node src/server.${ext}`,
      dev: `nodemon src/server.${ext}`,
      test: 'jest',
      'test:watch': 'jest --watch'
    },
    dependencies: {
      express: '^4.18.0',
      'http-proxy-middleware': '^2.0.0',
      'express-http-proxy': '^2.0.0',
      'dotenv': '^16.0.0',
      'cors': '^2.8.5',
      'helmet': '^7.0.0',
      'compression': '^1.7.0',
      'rate-limiter-flexible': '^3.0.0',
      'winston': '^3.8.0',
      'jsonwebtoken': '^9.0.0',
      'redis': '^4.0.0',
      'axios': '^1.4.0',
      'joi': '^17.9.0'
    },
    devDependencies: {
      nodemon: '^2.0.0',
      jest: '^29.0.0',
      supertest: '^6.0.0'
    }
  };

  await fs.writeJson(path.join(gatewayPath, 'package.json'), packageJson, { spaces: 2 });
}

async generateGatewayServer() {
  const gatewayPath = path.join(this.projectPath, 'api-gateway');
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  const serverContent = isCJS ? `const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('rate-limiter-flexible');
const winston = require('winston');
const jwt = require('jsonwebtoken');
const { createLogger, requestLogger } = require('../shared/utils/logger');
const { errorHandler, notFound } = require('../shared/middlewares/error');
const { authenticateToken, serviceAuth } = require('../shared/middlewares/auth');
const { SERVICE_URLS, SERVICE_NAMES, HTTP_STATUS } = require('../shared/constants');

require('dotenv').config();

const app = express();
const PORT = process.env.API_GATEWAY_PORT || 3000;
const logger = createLogger('api-gateway');

// Service registry (in production, this would be dynamic)
const serviceRegistry = {
  [SERVICE_NAMES.AUTH]: SERVICE_URLS[SERVICE_NAMES.AUTH],
  [SERVICE_NAMES.USER]: SERVICE_URLS[SERVICE_NAMES.USER],
  [SERVICE_NAMES.NOTIFICATION]: SERVICE_URLS[SERVICE_NAMES.NOTIFICATION],
  [SERVICE_NAMES.FILE]: SERVICE_URLS[SERVICE_NAMES.FILE],
  [SERVICE_NAMES.PAYMENT]: SERVICE_URLS[SERVICE_NAMES.PAYMENT],
  [SERVICE_NAMES.ANALYTICS]: SERVICE_URLS[SERVICE_NAMES.ANALYTICS]
};

// Rate limiting
const rateLimiter = new rateLimit.RateLimiterMemory({
  keyGenerator: (req) => req.ip,
  points: 1000, // Number of requests
  duration: 60, // Per 60 seconds
  blockDuration: 60 * 5 // Block for 5 minutes if exceeded
});

// Middleware
app.use(helmet());
app.use(compression());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger('api-gateway'));

// Rate limiting middleware
app.use(async (req, res, next) => {
  try {
    await rateLimiter.consume(req.ip);
    next();
  } catch (rejRes) {
    res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
      success: false,
      error: 'Too many requests from this IP, please try again later'
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'API Gateway is healthy',
    timestamp: new Date().toISOString(),
    services: Object.keys(serviceRegistry)
  });
});

// Service health check endpoint
app.get('/health/services', async (req, res) => {
  const healthChecks = {};
  
  for (const [serviceName, serviceUrl] of Object.entries(serviceRegistry)) {
    try {
      const response = await fetch(\`\${serviceUrl}/health\`);
      healthChecks[serviceName] = {
        status: response.status === 200 ? 'healthy' : 'unhealthy',
        statusCode: response.status,
        url: serviceUrl
      };
    } catch (error) {
      healthChecks[serviceName] = {
        status: 'unreachable',
        error: error.message,
        url: serviceUrl
      };
    }
  }

  const allHealthy = Object.values(healthChecks).every(service => service.status === 'healthy');
  
  res.status(allHealthy ? 200 : 503).json({
    success: allHealthy,
    message: allHealthy ? 'All services are healthy' : 'Some services are unhealthy',
    services: healthChecks
  });
});

// Authentication routes (no auth required)
app.use('/api/auth', createProxyMiddleware({
  target: serviceRegistry[SERVICE_NAMES.AUTH],
  changeOrigin: true,
  pathRewrite: {
    '^/api/auth': '/api/auth'
  },
  on: {
    proxyReq: (proxyReq, req, res) => {
      logger.info(\`Proxying auth request: \${req.method} \${req.url}\`);
    },
    error: (err, req, res) => {
      logger.error('Auth service proxy error:', err);
      res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
        success: false,
        error: 'Authentication service is currently unavailable'
      });
    }
  }
}));

// Public routes (no authentication required)
const publicRoutes = [
  '/api/auth/register',
  '/api/auth/login',
  '/api/auth/refresh-token',
  '/api/auth/validate-token'
];

// Authentication middleware for protected routes
app.use((req, res, next) => {
  // Skip auth for public routes
  if (publicRoutes.some(route => req.path.startsWith(route))) {
    return next();
  }
  
  // Skip auth for health checks
  if (req.path.startsWith('/health')) {
    return next();
  }
  
  // Authenticate all other routes
  authenticateToken(req, res, next);
});

// Service routing with authentication
app.use('/api/users', createProxyMiddleware({
  target: serviceRegistry[SERVICE_NAMES.USER],
  changeOrigin: true,
  pathRewrite: {
    '^/api/users': '/api/user'
  },
  on: {
    proxyReq: (proxyReq, req, res) => {
      // Add user context to headers for service-to-service communication
      if (req.user) {
        proxyReq.setHeader('x-user-id', req.user.userId);
        proxyReq.setHeader('x-user-role', req.user.role);
      }
      logger.info(\`Proxying user request: \${req.method} \${req.url}\`);
    },
    error: (err, req, res) => {
      logger.error('User service proxy error:', err);
      res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
        success: false,
        error: 'User service is currently unavailable'
      });
    }
  }
}));

app.use('/api/notifications', createProxyMiddleware({
  target: serviceRegistry[SERVICE_NAMES.NOTIFICATION],
  changeOrigin: true,
  pathRewrite: {
    '^/api/notifications': '/api/notification'
  },
  on: {
    proxyReq: (proxyReq, req, res) => {
      if (req.user) {
        proxyReq.setHeader('x-user-id', req.user.userId);
      }
      logger.info(\`Proxying notification request: \${req.method} \${req.url}\`);
    },
    error: (err, req, res) => {
      logger.error('Notification service proxy error:', err);
      res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
        success: false,
        error: 'Notification service is currently unavailable'
      });
    }
  }
}));

app.use('/api/files', createProxyMiddleware({
  target: serviceRegistry[SERVICE_NAMES.FILE],
  changeOrigin: true,
  pathRewrite: {
    '^/api/files': '/api/file'
  },
  on: {
    proxyReq: (proxyReq, req, res) => {
      if (req.user) {
        proxyReq.setHeader('x-user-id', req.user.userId);
        proxyReq.setHeader('x-user-role', req.user.role);
      }
      logger.info(\`Proxying file request: \${req.method} \${req.url}\`);
    },
    error: (err, req, res) => {
      logger.error('File service proxy error:', err);
      res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
        success: false,
        error: 'File service is currently unavailable'
      });
    }
  }
}));

app.use('/api/payments', createProxyMiddleware({
  target: serviceRegistry[SERVICE_NAMES.PAYMENT],
  changeOrigin: true,
  pathRewrite: {
    '^/api/payments': '/api/payment'
  },
  on: {
    proxyReq: (proxyReq, req, res) => {
      if (req.user) {
        proxyReq.setHeader('x-user-id', req.user.userId);
        proxyReq.setHeader('x-user-role', req.user.role);
      }
      logger.info(\`Proxying payment request: \${req.method} \${req.url}\`);
    },
    error: (err, req, res) => {
      logger.error('Payment service proxy error:', err);
      res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
        success: false,
        error: 'Payment service is currently unavailable'
      });
    }
  }
}));

app.use('/api/analytics', createProxyMiddleware({
  target: serviceRegistry[SERVICE_NAMES.ANALYTICS],
  changeOrigin: true,
  pathRewrite: {
    '^/api/analytics': '/api/analytics'
  },
  on: {
    proxyReq: (proxyReq, req, res) => {
      if (req.user) {
        proxyReq.setHeader('x-user-id', req.user.userId);
      }
      logger.info(\`Proxying analytics request: \${req.method} \${req.url}\`);
    },
    error: (err, req, res) => {
      logger.error('Analytics service proxy error:', err);
      res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
        success: false,
        error: 'Analytics service is currently unavailable'
      });
    }
  }
}));

// Service-to-service communication endpoint (protected with service auth)
app.use('/internal', serviceAuth, (req, res, next) => {
  const serviceName = req.service.service;
  const targetService = serviceRegistry[serviceName];
  
  if (!targetService) {
    return res.status(HTTP_STATUS.NOT_FOUND).json({
      success: false,
      error: \`Service \${serviceName} not found\`
    });
  }
  
  // Remove /internal prefix and route to the appropriate service
  const newPath = req.path.replace(/^\\/internal/, '');
  
  createProxyMiddleware({
    target: targetService,
    changeOrigin: true,
    pathRewrite: {
      '^/internal': ''
    },
    on: {
      proxyReq: (proxyReq, req, res) => {
        logger.info(\`Internal service request: \${serviceName} - \${req.method} \${newPath}\`);
      }
    }
  })(req, res, next);
});

// Error handling
app.use(notFound);
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

const startServer = () => {
  app.listen(PORT, () => {
    logger.info(\`API Gateway running on port \${PORT}\`);
    logger.info(\`Environment: \${process.env.NODE_ENV || 'development'}\`);
    logger.info('Registered services:', Object.keys(serviceRegistry));
  });
};

startServer();

module.exports = app;
` : `import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import winston from 'winston';
import jwt from 'jsonwebtoken';
import { createLogger, requestLogger } from '../shared/utils/logger.js';
import { errorHandler, notFound } from '../shared/middlewares/error.js';
import { authenticateToken, serviceAuth } from '../shared/middlewares/auth.js';
import { SERVICE_URLS, SERVICE_NAMES, HTTP_STATUS } from '../shared/constants/index.js';
import 'dotenv/config';

const app = express();
const PORT = process.env.API_GATEWAY_PORT || 3000;
const logger = createLogger('api-gateway');

const serviceRegistry = {
  [SERVICE_NAMES.AUTH]: SERVICE_URLS[SERVICE_NAMES.AUTH],
  [SERVICE_NAMES.USER]: SERVICE_URLS[SERVICE_NAMES.USER],
  [SERVICE_NAMES.NOTIFICATION]: SERVICE_URLS[SERVICE_NAMES.NOTIFICATION],
  [SERVICE_NAMES.FILE]: SERVICE_URLS[SERVICE_NAMES.FILE],
  [SERVICE_NAMES.PAYMENT]: SERVICE_URLS[SERVICE_NAMES.PAYMENT],
  [SERVICE_NAMES.ANALYTICS]: SERVICE_URLS[SERVICE_NAMES.ANALYTICS]
};

const rateLimiter = new RateLimiterMemory({
  keyGenerator: (req) => req.ip,
  points: 1000,
  duration: 60,
  blockDuration: 60 * 5
});

app.use(helmet());
app.use(compression());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger('api-gateway'));

app.use(async (req, res, next) => {
  try {
    await rateLimiter.consume(req.ip);
    next();
  } catch (rejRes) {
    res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
      success: false,
      error: 'Too many requests from this IP, please try again later'
    });
  }
});

app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'API Gateway is healthy',
    timestamp: new Date().toISOString(),
    services: Object.keys(serviceRegistry)
  });
});

app.get('/health/services', async (req, res) => {
  const healthChecks = {};
  
  for (const [serviceName, serviceUrl] of Object.entries(serviceRegistry)) {
    try {
      const response = await fetch(\`\${serviceUrl}/health\`);
      healthChecks[serviceName] = {
        status: response.status === 200 ? 'healthy' : 'unhealthy',
        statusCode: response.status,
        url: serviceUrl
      };
    } catch (error) {
      healthChecks[serviceName] = {
        status: 'unreachable',
        error: error.message,
        url: serviceUrl
      };
    }
  }

  const allHealthy = Object.values(healthChecks).every(service => service.status === 'healthy');
  
  res.status(allHealthy ? 200 : 503).json({
    success: allHealthy,
    message: allHealthy ? 'All services are healthy' : 'Some services are unhealthy',
    services: healthChecks
  });
});

app.use('/api/auth', createProxyMiddleware({
  target: serviceRegistry[SERVICE_NAMES.AUTH],
  changeOrigin: true,
  pathRewrite: {
    '^/api/auth': '/api/auth'
  },
  on: {
    proxyReq: (proxyReq, req, res) => {
      logger.info(\`Proxying auth request: \${req.method} \${req.url}\`);
    },
    error: (err, req, res) => {
      logger.error('Auth service proxy error:', err);
      res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
        success: false,
        error: 'Authentication service is currently unavailable'
      });
    }
  }
}));

const publicRoutes = [
  '/api/auth/register',
  '/api/auth/login',
  '/api/auth/refresh-token',
  '/api/auth/validate-token'
];

app.use((req, res, next) => {
  if (publicRoutes.some(route => req.path.startsWith(route))) {
    return next();
  }
  
  if (req.path.startsWith('/health')) {
    return next();
  }
  
  authenticateToken(req, res, next);
});

app.use('/api/users', createProxyMiddleware({
  target: serviceRegistry[SERVICE_NAMES.USER],
  changeOrigin: true,
  pathRewrite: {
    '^/api/users': '/api/user'
  },
  on: {
    proxyReq: (proxyReq, req, res) => {
      if (req.user) {
        proxyReq.setHeader('x-user-id', req.user.userId);
        proxyReq.setHeader('x-user-role', req.user.role);
      }
      logger.info(\`Proxying user request: \${req.method} \${req.url}\`);
    },
    error: (err, req, res) => {
      logger.error('User service proxy error:', err);
      res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
        success: false,
        error: 'User service is currently unavailable'
      });
    }
  }
}));

app.use('/api/notifications', createProxyMiddleware({
  target: serviceRegistry[SERVICE_NAMES.NOTIFICATION],
  changeOrigin: true,
  pathRewrite: {
    '^/api/notifications': '/api/notification'
  },
  on: {
    proxyReq: (proxyReq, req, res) => {
      if (req.user) {
        proxyReq.setHeader('x-user-id', req.user.userId);
      }
      logger.info(\`Proxying notification request: \${req.method} \${req.url}\`);
    },
    error: (err, req, res) => {
      logger.error('Notification service proxy error:', err);
      res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
        success: false,
        error: 'Notification service is currently unavailable'
      });
    }
  }
}));

app.use('/api/files', createProxyMiddleware({
  target: serviceRegistry[SERVICE_NAMES.FILE],
  changeOrigin: true,
  pathRewrite: {
    '^/api/files': '/api/file'
  },
  on: {
    proxyReq: (proxyReq, req, res) => {
      if (req.user) {
        proxyReq.setHeader('x-user-id', req.user.userId);
        proxyReq.setHeader('x-user-role', req.user.role);
      }
      logger.info(\`Proxying file request: \${req.method} \${req.url}\`);
    },
    error: (err, req, res) => {
      logger.error('File service proxy error:', err);
      res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
        success: false,
        error: 'File service is currently unavailable'
      });
    }
  }
}));

app.use('/api/payments', createProxyMiddleware({
  target: serviceRegistry[SERVICE_NAMES.PAYMENT],
  changeOrigin: true,
  pathRewrite: {
    '^/api/payments': '/api/payment'
  },
  on: {
    proxyReq: (proxyReq, req, res) => {
      if (req.user) {
        proxyReq.setHeader('x-user-id', req.user.userId);
        proxyReq.setHeader('x-user-role', req.user.role);
      }
      logger.info(\`Proxying payment request: \${req.method} \${req.url}\`);
    },
    error: (err, req, res) => {
      logger.error('Payment service proxy error:', err);
      res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
        success: false,
        error: 'Payment service is currently unavailable'
      });
    }
  }
}));

app.use('/api/analytics', createProxyMiddleware({
  target: serviceRegistry[SERVICE_NAMES.ANALYTICS],
  changeOrigin: true,
  pathRewrite: {
    '^/api/analytics': '/api/analytics'
  },
  on: {
    proxyReq: (proxyReq, req, res) => {
      if (req.user) {
        proxyReq.setHeader('x-user-id', req.user.userId);
      }
      logger.info(\`Proxying analytics request: \${req.method} \${req.url}\`);
    },
    error: (err, req, res) => {
      logger.error('Analytics service proxy error:', err);
      res.status(HTTP_STATUS.SERVICE_UNAVAILABLE).json({
        success: false,
        error: 'Analytics service is currently unavailable'
      });
    }
  }
}));

app.use('/internal', serviceAuth, (req, res, next) => {
  const serviceName = req.service.service;
  const targetService = serviceRegistry[serviceName];
  
  if (!targetService) {
    return res.status(HTTP_STATUS.NOT_FOUND).json({
      success: false,
      error: \`Service \${serviceName} not found\`
    });
  }
  
  const newPath = req.path.replace(/^\\/internal/, '');
  
  createProxyMiddleware({
    target: targetService,
    changeOrigin: true,
    pathRewrite: {
      '^/internal': ''
    },
    on: {
      proxyReq: (proxyReq, req, res) => {
        logger.info(\`Internal service request: \${serviceName} - \${req.method} \${newPath}\`);
      }
    }
  })(req, res, next);
});

app.use(notFound);
app.use(errorHandler);

process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

const startServer = () => {
  app.listen(PORT, () => {
    logger.info(\`API Gateway running on port \${PORT}\`);
    logger.info(\`Environment: \${process.env.NODE_ENV || 'development'}\`);
    logger.info('Registered services:', Object.keys(serviceRegistry));
  });
};

startServer();

export default app;
`;

  await fs.writeFile(
    path.join(gatewayPath, `src/server.${ext}`),
    serverContent
  );

  // Generate API Gateway environment file
  const envContent = `# API Gateway Configuration
API_GATEWAY_PORT=3000
NODE_ENV=development

# JWT Configuration
JWT_ACCESS_SECRET=your-jwt-access-secret-change-in-production
JWT_REFRESH_SECRET=your-jwt-refresh-secret-change-in-production
JWT_SERVICE_SECRET=your-jwt-service-secret-change-in-production

# Service URLs
AUTH_SERVICE_URL=http://localhost:3001
USER_SERVICE_URL=http://localhost:3002
NOTIFICATION_SERVICE_URL=http://localhost:3003
FILE_SERVICE_URL=http://localhost:3004
PAYMENT_SERVICE_URL=http://localhost:3005
ANALYTICS_SERVICE_URL=http://localhost:3006

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173,http://localhost:8080

# Redis Configuration (for rate limiting)
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=info
`;

  await fs.writeFile(
    path.join(gatewayPath, '.env.example'),
    envContent
  );
}

async generateGatewayRoutes() {
  const gatewayPath = path.join(this.projectPath, 'api-gateway');
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  // Routes configuration file
  const routesConfig = isCJS ? `const { SERVICE_URLS, SERVICE_NAMES } = require('../../shared/constants');

// Route configuration for API Gateway
const routes = [
  {
    path: '/api/auth',
    service: SERVICE_NAMES.AUTH,
    target: SERVICE_URLS[SERVICE_NAMES.AUTH],
    public: true, // Authentication routes are public
    rewrite: {
      '^/api/auth': '/api/auth'
    }
  },
  {
    path: '/api/users',
    service: SERVICE_NAMES.USER,
    target: SERVICE_URLS[SERVICE_NAMES.USER],
    public: false,
    rewrite: {
      '^/api/users': '/api/user'
    },
    headers: (req) => ({
      'x-user-id': req.user?.userId,
      'x-user-role': req.user?.role
    })
  },
  {
    path: '/api/notifications',
    service: SERVICE_NAMES.NOTIFICATION,
    target: SERVICE_URLS[SERVICE_NAMES.NOTIFICATION],
    public: false,
    rewrite: {
      '^/api/notifications': '/api/notification'
    },
    headers: (req) => ({
      'x-user-id': req.user?.userId
    })
  },
  {
    path: '/api/files',
    service: SERVICE_NAMES.FILE,
    target: SERVICE_URLS[SERVICE_NAMES.FILE],
    public: false,
    rewrite: {
      '^/api/files': '/api/file'
    },
    headers: (req) => ({
      'x-user-id': req.user?.userId,
      'x-user-role': req.user?.role
    })
  },
  {
    path: '/api/payments',
    service: SERVICE_NAMES.PAYMENT,
    target: SERVICE_URLS[SERVICE_NAMES.PAYMENT],
    public: false,
    rewrite: {
      '^/api/payments': '/api/payment'
    },
    headers: (req) => ({
      'x-user-id': req.user?.userId,
      'x-user-role': req.user?.role
    })
  },
  {
    path: '/api/analytics',
    service: SERVICE_NAMES.ANALYTICS,
    target: SERVICE_URLS[SERVICE_NAMES.ANALYTICS],
    public: false,
    rewrite: {
      '^/api/analytics': '/api/analytics'
    },
    headers: (req) => ({
      'x-user-id': req.user?.userId
    })
  }
];

// Public routes that don't require authentication
const publicRoutes = [
  '/api/auth/register',
  '/api/auth/login',
  '/api/auth/refresh-token',
  '/api/auth/validate-token',
  '/health',
  '/health/services'
];

// Service discovery routes (for internal service communication)
const serviceRoutes = [
  {
    path: '/internal/auth',
    service: SERVICE_NAMES.AUTH,
    target: SERVICE_URLS[SERVICE_NAMES.AUTH],
    rewrite: {
      '^/internal/auth': '/api/auth'
    }
  },
  {
    path: '/internal/user',
    service: SERVICE_NAMES.USER,
    target: SERVICE_URLS[SERVICE_NAMES.USER],
    rewrite: {
      '^/internal/user': '/api/user'
    }
  },
  {
    path: '/internal/notification',
    service: SERVICE_NAMES.NOTIFICATION,
    target: SERVICE_URLS[SERVICE_NAMES.NOTIFICATION],
    rewrite: {
      '^/internal/notification': '/api/notification'
    }
  },
  {
    path: '/internal/file',
    service: SERVICE_NAMES.FILE,
    target: SERVICE_URLS[SERVICE_NAMES.FILE],
    rewrite: {
      '^/internal/file': '/api/file'
    }
  },
  {
    path: '/internal/payment',
    service: SERVICE_NAMES.PAYMENT,
    target: SERVICE_URLS[SERVICE_NAMES.PAYMENT],
    rewrite: {
      '^/internal/payment': '/api/payment'
    }
  },
  {
    path: '/internal/analytics',
    service: SERVICE_NAMES.ANALYTICS,
    target: SERVICE_URLS[SERVICE_NAMES.ANALYTICS],
    rewrite: {
      '^/internal/analytics': '/api/analytics'
    }
  }
];

module.exports = {
  routes,
  publicRoutes,
  serviceRoutes
};
` : `import { SERVICE_URLS, SERVICE_NAMES } from '../../shared/constants/index.js';

export const routes = [
  {
    path: '/api/auth',
    service: SERVICE_NAMES.AUTH,
    target: SERVICE_URLS[SERVICE_NAMES.AUTH],
    public: true,
    rewrite: {
      '^/api/auth': '/api/auth'
    }
  },
  {
    path: '/api/users',
    service: SERVICE_NAMES.USER,
    target: SERVICE_URLS[SERVICE_NAMES.USER],
    public: false,
    rewrite: {
      '^/api/users': '/api/user'
    },
    headers: (req) => ({
      'x-user-id': req.user?.userId,
      'x-user-role': req.user?.role
    })
  },
  {
    path: '/api/notifications',
    service: SERVICE_NAMES.NOTIFICATION,
    target: SERVICE_URLS[SERVICE_NAMES.NOTIFICATION],
    public: false,
    rewrite: {
      '^/api/notifications': '/api/notification'
    },
    headers: (req) => ({
      'x-user-id': req.user?.userId
    })
  },
  {
    path: '/api/files',
    service: SERVICE_NAMES.FILE,
    target: SERVICE_URLS[SERVICE_NAMES.FILE],
    public: false,
    rewrite: {
      '^/api/files': '/api/file'
    },
    headers: (req) => ({
      'x-user-id': req.user?.userId,
      'x-user-role': req.user?.role
    })
  },
  {
    path: '/api/payments',
    service: SERVICE_NAMES.PAYMENT,
    target: SERVICE_URLS[SERVICE_NAMES.PAYMENT],
    public: false,
    rewrite: {
      '^/api/payments': '/api/payment'
    },
    headers: (req) => ({
      'x-user-id': req.user?.userId,
      'x-user-role': req.user?.role
    })
  },
  {
    path: '/api/analytics',
    service: SERVICE_NAMES.ANALYTICS,
    target: SERVICE_URLS[SERVICE_NAMES.ANALYTICS],
    public: false,
    rewrite: {
      '^/api/analytics': '/api/analytics'
    },
    headers: (req) => ({
      'x-user-id': req.user?.userId
    })
  }
];

export const publicRoutes = [
  '/api/auth/register',
  '/api/auth/login',
  '/api/auth/refresh-token',
  '/api/auth/validate-token',
  '/health',
  '/health/services'
];

export const serviceRoutes = [
  {
    path: '/internal/auth',
    service: SERVICE_NAMES.AUTH,
    target: SERVICE_URLS[SERVICE_NAMES.AUTH],
    rewrite: {
      '^/internal/auth': '/api/auth'
    }
  },
  {
    path: '/internal/user',
    service: SERVICE_NAMES.USER,
    target: SERVICE_URLS[SERVICE_NAMES.USER],
    rewrite: {
      '^/internal/user': '/api/user'
    }
  },
  {
    path: '/internal/notification',
    service: SERVICE_NAMES.NOTIFICATION,
    target: SERVICE_URLS[SERVICE_NAMES.NOTIFICATION],
    rewrite: {
      '^/internal/notification': '/api/notification'
    }
  },
  {
    path: '/internal/file',
    service: SERVICE_NAMES.FILE,
    target: SERVICE_URLS[SERVICE_NAMES.FILE],
    rewrite: {
      '^/internal/file': '/api/file'
    }
  },
  {
    path: '/internal/payment',
    service: SERVICE_NAMES.PAYMENT,
    target: SERVICE_URLS[SERVICE_NAMES.PAYMENT],
    rewrite: {
      '^/internal/payment': '/api/payment'
    }
  },
  {
    path: '/internal/analytics',
    service: SERVICE_NAMES.ANALYTICS,
    target: SERVICE_URLS[SERVICE_NAMES.ANALYTICS],
    rewrite: {
      '^/internal/analytics': '/api/analytics'
    }
  }
];
`;

  await fs.writeFile(
    path.join(gatewayPath, `src/routes/config.${ext}`),
    routesConfig
  );

  // Generate route middleware
  const routeMiddleware = isCJS ? `const { createProxyMiddleware } = require('http-proxy-middleware');
const { routes, publicRoutes, serviceRoutes } = require('./config');
const { authenticateToken, serviceAuth } = require('../../../shared/middlewares/auth');
const { createLogger } = require('../../../shared/utils/logger');

const logger = createLogger('api-gateway-routes');

// Create proxy middleware for each route
const createRouteProxies = () => {
  const proxies = [];

  routes.forEach(route => {
    const proxy = createProxyMiddleware(route.path, {
      target: route.target,
      changeOrigin: true,
      pathRewrite: route.rewrite,
      on: {
        proxyReq: (proxyReq, req, res) => {
          // Add custom headers if defined
          if (route.headers && typeof route.headers === 'function') {
            const headers = route.headers(req);
            Object.entries(headers).forEach(([key, value]) => {
              if (value) {
                proxyReq.setHeader(key, value);
              }
            });
          }
          
          logger.info(\`Routing \${req.method} \${req.originalUrl} to \${route.service} service\`);
        },
        proxyRes: (proxyRes, req, res) => {
          logger.info(\`\${route.service} service responded with status \${proxyRes.statusCode}\`);
        },
        error: (err, req, res) => {
          logger.error(\`Error routing to \${route.service} service:\`, err);
          res.status(503).json({
            success: false,
            error: \`\${route.service} service is currently unavailable\`
          });
        }
      }
    });

    proxies.push({
      path: route.path,
      proxy,
      public: route.public
    });
  });

  return proxies;
};

// Create service-to-service proxies
const createServiceProxies = () => {
  const proxies = [];

  serviceRoutes.forEach(route => {
    const proxy = createProxyMiddleware(route.path, {
      target: route.target,
      changeOrigin: true,
      pathRewrite: route.rewrite,
      on: {
        proxyReq: (proxyReq, req, res) => {
          logger.info(\`Internal service routing: \${req.service?.service} -> \${route.service}\`);
        },
        error: (err, req, res) => {
          logger.error(\`Error in internal service routing to \${route.service}:\`, err);
          res.status(503).json({
            success: false,
            error: \`\${route.service} service is currently unavailable\`
          });
        }
      }
    });

    proxies.push({
      path: route.path,
      proxy,
      requiresServiceAuth: true
    });
  });

  return proxies;
};

// Check if route is public
const isPublicRoute = (req) => {
  return publicRoutes.some(publicRoute => req.path.startsWith(publicRoute));
};

// Apply routing middleware
const applyRoutes = (app) => {
  const routeProxies = createRouteProxies();
  const serviceProxies = createServiceProxies();

  // Apply service-to-service routes (protected by service auth)
  serviceProxies.forEach(({ path, proxy, requiresServiceAuth }) => {
    if (requiresServiceAuth) {
      app.use(path, serviceAuth, proxy);
    } else {
      app.use(path, proxy);
    }
  });

  // Apply regular routes with authentication
  routeProxies.forEach(({ path, proxy, public: isPublic }) => {
    if (isPublic) {
      app.use(path, proxy);
    } else {
      app.use(path, authenticateToken, proxy);
    }
  });

  logger.info(\`Applied \${routeProxies.length} regular routes and \${serviceProxies.length} service routes\`);
};

module.exports = {
  applyRoutes,
  isPublicRoute,
  createRouteProxies,
  createServiceProxies
};
` : `import { createProxyMiddleware } from 'http-proxy-middleware';
import { routes, publicRoutes, serviceRoutes } from './config.js';
import { authenticateToken, serviceAuth } from '../../../shared/middlewares/auth.js';
import { createLogger } from '../../../shared/utils/logger.js';

const logger = createLogger('api-gateway-routes');

export const createRouteProxies = () => {
  const proxies = [];

  routes.forEach(route => {
    const proxy = createProxyMiddleware(route.path, {
      target: route.target,
      changeOrigin: true,
      pathRewrite: route.rewrite,
      on: {
        proxyReq: (proxyReq, req, res) => {
          if (route.headers && typeof route.headers === 'function') {
            const headers = route.headers(req);
            Object.entries(headers).forEach(([key, value]) => {
              if (value) {
                proxyReq.setHeader(key, value);
              }
            });
          }
          
          logger.info(\`Routing \${req.method} \${req.originalUrl} to \${route.service} service\`);
        },
        proxyRes: (proxyRes, req, res) => {
          logger.info(\`\${route.service} service responded with status \${proxyRes.statusCode}\`);
        },
        error: (err, req, res) => {
          logger.error(\`Error routing to \${route.service} service:\`, err);
          res.status(503).json({
            success: false,
            error: \`\${route.service} service is currently unavailable\`
          });
        }
      }
    });

    proxies.push({
      path: route.path,
      proxy,
      public: route.public
    });
  });

  return proxies;
};

export const createServiceProxies = () => {
  const proxies = [];

  serviceRoutes.forEach(route => {
    const proxy = createProxyMiddleware(route.path, {
      target: route.target,
      changeOrigin: true,
      pathRewrite: route.rewrite,
      on: {
        proxyReq: (proxyReq, req, res) => {
          logger.info(\`Internal service routing: \${req.service?.service} -> \${route.service}\`);
        },
        error: (err, req, res) => {
          logger.error(\`Error in internal service routing to \${route.service}:\`, err);
          res.status(503).json({
            success: false,
            error: \`\${route.service} service is currently unavailable\`
          });
        }
      }
    });

    proxies.push({
      path: route.path,
      proxy,
      requiresServiceAuth: true
    });
  });

  return proxies;
};

export const isPublicRoute = (req) => {
  return publicRoutes.some(publicRoute => req.path.startsWith(publicRoute));
};

export const applyRoutes = (app) => {
  const routeProxies = createRouteProxies();
  const serviceProxies = createServiceProxies();

  serviceProxies.forEach(({ path, proxy, requiresServiceAuth }) => {
    if (requiresServiceAuth) {
      app.use(path, serviceAuth, proxy);
    } else {
      app.use(path, proxy);
    }
  });

  routeProxies.forEach(({ path, proxy, public: isPublic }) => {
    if (isPublic) {
      app.use(path, proxy);
    } else {
      app.use(path, authenticateToken, proxy);
    }
  });

  logger.info(\`Applied \${routeProxies.length} regular routes and \${serviceProxies.length} service routes\`);
};
`;

  await fs.writeFile(
    path.join(gatewayPath, `src/routes/middleware.${ext}`),
    routeMiddleware
  );
}
  async generateServiceDiscovery() {
    const discoveryPath = path.join(this.projectPath, 'service-discovery');
    
    // Generate service discovery configuration
    await this.generateDiscoveryConfig();
  }
  async generateServiceDiscovery() {
  const discoveryPath = path.join(this.projectPath, 'service-discovery');
  
  // Create service discovery directory structure
  const discoveryDirs = [
    'src/config',
    'src/services',
    'src/utils',
    'src/middlewares'
  ];

  for (const dir of discoveryDirs) {
    await this.ensureDirectory(path.join(discoveryPath, dir));
  }

  // Generate service discovery configuration
  await this.generateDiscoveryConfig();
  await this.generateDiscoveryServer();
  await this.generateDiscoveryService();
  await this.generateDiscoveryPackageJson();
}

async generateDiscoveryConfig() {
  const discoveryPath = path.join(this.projectPath, 'service-discovery');
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  // Main configuration file
  const discoveryConfig = isCJS ? `const { SERVICE_NAMES, SERVICE_PORTS } = require('../../shared/constants');

// Service discovery configuration
const discoveryConfig = {
  // Server configuration
  server: {
    port: process.env.SERVICE_DISCOVERY_PORT || 8500,
    host: process.env.SERVICE_DISCOVERY_HOST || 'localhost',
    environment: process.env.NODE_ENV || 'development'
  },

  // Service registry configuration
  registry: {
    // How often to check service health (in milliseconds)
    healthCheckInterval: 30000, // 30 seconds
    
    // Timeout for health checks (in milliseconds)
    healthCheckTimeout: 5000, // 5 seconds
    
    // Number of consecutive failures before marking service as unhealthy
    maxFailures: 3,
    
    // How long to keep service in registry after last heartbeat (in milliseconds)
    serviceTTL: 60000, // 1 minute
  },

  // Default services (static configuration - in production this would be dynamic)
  defaultServices: {
    [SERVICE_NAMES.AUTH]: {
      name: SERVICE_NAMES.AUTH,
      url: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.AUTH]}\`,
      port: SERVICE_PORTS[SERVICE_NAMES.AUTH],
      version: '1.0.0',
      endpoints: [
        '/api/auth/register',
        '/api/auth/login',
        '/api/auth/refresh-token',
        '/api/auth/validate-token'
      ],
      healthCheck: '/health'
    },
    [SERVICE_NAMES.USER]: {
      name: SERVICE_NAMES.USER,
      url: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.USER]}\`,
      port: SERVICE_PORTS[SERVICE_NAMES.USER],
      version: '1.0.0',
      endpoints: [
        '/api/user/profile',
        '/api/user/update',
        '/api/user/list'
      ],
      healthCheck: '/health'
    },
    [SERVICE_NAMES.NOTIFICATION]: {
      name: SERVICE_NAMES.NOTIFICATION,
      url: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.NOTIFICATION]}\`,
      port: SERVICE_PORTS[SERVICE_NAMES.NOTIFICATION],
      version: '1.0.0',
      endpoints: [
        '/api/notification/send',
        '/api/notification/bulk',
        '/api/notification/status'
      ],
      healthCheck: '/health'
    },
    [SERVICE_NAMES.FILE]: {
      name: SERVICE_NAMES.FILE,
      url: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.FILE]}\`,
      port: SERVICE_PORTS[SERVICE_NAMES.FILE],
      version: '1.0.0',
      endpoints: [
        '/api/file/upload',
        '/api/file/download',
        '/api/file/list',
        '/api/file/delete'
      ],
      healthCheck: '/health'
    },
    [SERVICE_NAMES.PAYMENT]: {
      name: SERVICE_NAMES.PAYMENT,
      url: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.PAYMENT]}\`,
      port: SERVICE_PORTS[SERVICE_NAMES.PAYMENT],
      version: '1.0.0',
      endpoints: [
        '/api/payment/create',
        '/api/payment/confirm',
        '/api/payment/history',
        '/api/payment/refund'
      ],
      healthCheck: '/health'
    },
    [SERVICE_NAMES.ANALYTICS]: {
      name: SERVICE_NAMES.ANALYTICS,
      url: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.ANALYTICS]}\`,
      port: SERVICE_PORTS[SERVICE_NAMES.ANALYTICS],
      version: '1.0.0',
      endpoints: [
        '/api/analytics/track',
        '/api/analytics/stats',
        '/api/analytics/realtime',
        '/api/analytics/export'
      ],
      healthCheck: '/health'
    }
  },

  // Load balancing configuration
  loadBalancing: {
    strategy: 'round-robin', // 'round-robin', 'least-connections', 'random'
    stickySessions: false,
    sessionDuration: 3600000 // 1 hour in milliseconds
  },

  // Circuit breaker configuration
  circuitBreaker: {
    enabled: true,
    failureThreshold: 5,
    successThreshold: 2,
    timeout: 30000, // 30 seconds
    resetTimeout: 60000 // 1 minute
  },

  // Caching configuration
  caching: {
    enabled: true,
    ttl: 30000, // 30 seconds
    maxSize: 1000 // Maximum number of cached entries
  }
};

module.exports = discoveryConfig;
` : `import { SERVICE_NAMES, SERVICE_PORTS } from '../../shared/constants/index.js';

export const discoveryConfig = {
  server: {
    port: process.env.SERVICE_DISCOVERY_PORT || 8500,
    host: process.env.SERVICE_DISCOVERY_HOST || 'localhost',
    environment: process.env.NODE_ENV || 'development'
  },

  registry: {
    healthCheckInterval: 30000,
    healthCheckTimeout: 5000,
    maxFailures: 3,
    serviceTTL: 60000,
  },

  defaultServices: {
    [SERVICE_NAMES.AUTH]: {
      name: SERVICE_NAMES.AUTH,
      url: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.AUTH]}\`,
      port: SERVICE_PORTS[SERVICE_NAMES.AUTH],
      version: '1.0.0',
      endpoints: [
        '/api/auth/register',
        '/api/auth/login',
        '/api/auth/refresh-token',
        '/api/auth/validate-token'
      ],
      healthCheck: '/health'
    },
    [SERVICE_NAMES.USER]: {
      name: SERVICE_NAMES.USER,
      url: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.USER]}\`,
      port: SERVICE_PORTS[SERVICE_NAMES.USER],
      version: '1.0.0',
      endpoints: [
        '/api/user/profile',
        '/api/user/update',
        '/api/user/list'
      ],
      healthCheck: '/health'
    },
    [SERVICE_NAMES.NOTIFICATION]: {
      name: SERVICE_NAMES.NOTIFICATION,
      url: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.NOTIFICATION]}\`,
      port: SERVICE_PORTS[SERVICE_NAMES.NOTIFICATION],
      version: '1.0.0',
      endpoints: [
        '/api/notification/send',
        '/api/notification/bulk',
        '/api/notification/status'
      ],
      healthCheck: '/health'
    },
    [SERVICE_NAMES.FILE]: {
      name: SERVICE_NAMES.FILE,
      url: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.FILE]}\`,
      port: SERVICE_PORTS[SERVICE_NAMES.FILE],
      version: '1.0.0',
      endpoints: [
        '/api/file/upload',
        '/api/file/download',
        '/api/file/list',
        '/api/file/delete'
      ],
      healthCheck: '/health'
    },
    [SERVICE_NAMES.PAYMENT]: {
      name: SERVICE_NAMES.PAYMENT,
      url: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.PAYMENT]}\`,
      port: SERVICE_PORTS[SERVICE_NAMES.PAYMENT],
      version: '1.0.0',
      endpoints: [
        '/api/payment/create',
        '/api/payment/confirm',
        '/api/payment/history',
        '/api/payment/refund'
      ],
      healthCheck: '/health'
    },
    [SERVICE_NAMES.ANALYTICS]: {
      name: SERVICE_NAMES.ANALYTICS,
      url: \`http://localhost:\${SERVICE_PORTS[SERVICE_NAMES.ANALYTICS]}\`,
      port: SERVICE_PORTS[SERVICE_NAMES.ANALYTICS],
      version: '1.0.0',
      endpoints: [
        '/api/analytics/track',
        '/api/analytics/stats',
        '/api/analytics/realtime',
        '/api/analytics/export'
      ],
      healthCheck: '/health'
    }
  },

  loadBalancing: {
    strategy: 'round-robin',
    stickySessions: false,
    sessionDuration: 3600000
  },

  circuitBreaker: {
    enabled: true,
    failureThreshold: 5,
    successThreshold: 2,
    timeout: 30000,
    resetTimeout: 60000
  },

  caching: {
    enabled: true,
    ttl: 30000,
    maxSize: 1000
  }
};

export default discoveryConfig;
`;

  await fs.writeFile(
    path.join(discoveryPath, `src/config/discovery.${ext}`),
    discoveryConfig
  );

  // Generate environment file for service discovery
  const envContent = `# Service Discovery Configuration
SERVICE_DISCOVERY_PORT=8500
SERVICE_DISCOVERY_HOST=localhost
NODE_ENV=development

# Redis Configuration (for service registry)
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=
REDIS_DB=0

# Service Health Check Configuration
HEALTH_CHECK_INTERVAL=30000
HEALTH_CHECK_TIMEOUT=5000
MAX_HEALTH_FAILURES=3

# Service Registration
SERVICE_REGISTRATION_ENABLED=true
SERVICE_HEARTBEAT_INTERVAL=15000

# Logging
LOG_LEVEL=info
LOG_SERVICES_HEALTH=false

# Security
API_KEY=your-service-discovery-api-key-change-in-production
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8500
`;

  await fs.writeFile(
    path.join(discoveryPath, '.env.example'),
    envContent
  );
}

async generateDiscoveryServer() {
  const discoveryPath = path.join(this.projectPath, 'service-discovery');
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  const serverContent = isCJS ? `const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('rate-limiter-flexible');
const { createLogger, requestLogger } = require('../../shared/utils/logger');
const { errorHandler, notFound } = require('../../shared/middlewares/error');
const discoveryConfig = require('./config/discovery');
const { ServiceRegistry } = require('./services/ServiceRegistry');
const { HealthMonitor } = require('./services/HealthMonitor');
const { LoadBalancer } = require('./services/LoadBalancer');

require('dotenv').config();

const app = express();
const PORT = discoveryConfig.server.port;
const logger = createLogger('service-discovery');

// Initialize core components
const serviceRegistry = new ServiceRegistry();
const healthMonitor = new HealthMonitor(serviceRegistry, discoveryConfig);
const loadBalancer = new LoadBalancer(serviceRegistry, discoveryConfig);

// Rate limiting
const rateLimiter = new rateLimit.RateLimiterMemory({
  keyGenerator: (req) => req.ip,
  points: 1000,
  duration: 60,
  blockDuration: 60 * 5
});

// Middleware
app.use(helmet());
app.use(compression());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger('service-discovery'));

// Rate limiting middleware
app.use(async (req, res, next) => {
  try {
    await rateLimiter.consume(req.ip);
    next();
  } catch (rejRes) {
    res.status(429).json({
      success: false,
      error: 'Too many requests from this IP, please try again later'
    });
  }
});

// API key authentication for service registration endpoints
const authenticateService = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or missing API key'
    });
  }
  
  next();
};

// Health check endpoint
app.get('/health', (req, res) => {
  const registryStatus = serviceRegistry.getStatus();
  
  res.json({
    success: true,
    message: 'Service Discovery is healthy',
    timestamp: new Date().toISOString(),
    registry: registryStatus
  });
});

// Get all registered services
app.get('/services', (req, res) => {
  try {
    const services = serviceRegistry.getAllServices();
    
    res.json({
      success: true,
      data: {
        services,
        total: services.length,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    logger.error('Error fetching services:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch services'
    });
  }
});

// Get service by name
app.get('/services/:serviceName', (req, res) => {
  try {
    const { serviceName } = req.params;
    const service = serviceRegistry.getService(serviceName);
    
    if (!service) {
      return res.status(404).json({
        success: false,
        error: \`Service '\${serviceName}' not found\`
      });
    }
    
    res.json({
      success: true,
      data: service
    });
  } catch (error) {
    logger.error('Error fetching service:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch service'
    });
  }
});

// Get healthy instances of a service
app.get('/services/:serviceName/healthy', (req, res) => {
  try {
    const { serviceName } = req.params;
    const healthyInstances = serviceRegistry.getHealthyInstances(serviceName);
    
    if (healthyInstances.length === 0) {
      return res.status(404).json({
        success: false,
        error: \`No healthy instances found for service '\${serviceName}'\`
      });
    }
    
    res.json({
      success: true,
      data: {
        service: serviceName,
        instances: healthyInstances,
        count: healthyInstances.length
      }
    });
  } catch (error) {
    logger.error('Error fetching healthy instances:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch healthy instances'
    });
  }
});

// Service registration endpoint
app.post('/register', authenticateService, (req, res) => {
  try {
    const serviceData = req.body;
    
    if (!serviceData.name || !serviceData.url) {
      return res.status(400).json({
        success: false,
        error: 'Service name and URL are required'
      });
    }
    
    const registeredService = serviceRegistry.registerService(serviceData);
    
    logger.info(\`Service registered: \${serviceData.name} at \${serviceData.url}\`);
    
    res.status(201).json({
      success: true,
      message: \`Service '\${serviceData.name}' registered successfully\`,
      data: registeredService
    });
  } catch (error) {
    logger.error('Error registering service:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to register service'
    });
  }
});

// Service heartbeat endpoint
app.post('/heartbeat', authenticateService, (req, res) => {
  try {
    const { serviceName, instanceId } = req.body;
    
    if (!serviceName || !instanceId) {
      return res.status(400).json({
        success: false,
        error: 'Service name and instance ID are required'
      });
    }
    
    const updated = serviceRegistry.updateHeartbeat(serviceName, instanceId);
    
    if (!updated) {
      return res.status(404).json({
        success: false,
        error: \`Service '\${serviceName}' with instance '\${instanceId}' not found\`
      });
    }
    
    res.json({
      success: true,
      message: 'Heartbeat received'
    });
  } catch (error) {
    logger.error('Error processing heartbeat:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process heartbeat'
    });
  }
});

// Service unregistration endpoint
app.post('/unregister', authenticateService, (req, res) => {
  try {
    const { serviceName, instanceId } = req.body;
    
    if (!serviceName || !instanceId) {
      return res.status(400).json({
        success: false,
        error: 'Service name and instance ID are required'
      });
    }
    
    const unregistered = serviceRegistry.unregisterService(serviceName, instanceId);
    
    if (!unregistered) {
      return res.status(404).json({
        success: false,
        error: \`Service '\${serviceName}' with instance '\${instanceId}' not found\`
      });
    }
    
    logger.info(\`Service unregistered: \${serviceName} instance \${instanceId}\`);
    
    res.json({
      success: true,
      message: \`Service '\${serviceName}' unregistered successfully\`
    });
  } catch (error) {
    logger.error('Error unregistering service:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to unregister service'
    });
  }
});

// Load balancer endpoint - get next available instance
app.get('/balance/:serviceName', (req, res) => {
  try {
    const { serviceName } = req.params;
    const instance = loadBalancer.getNextInstance(serviceName);
    
    if (!instance) {
      return res.status(404).json({
        success: false,
        error: \`No available instances for service '\${serviceName}'\`
      });
    }
    
    res.json({
      success: true,
      data: instance
    });
  } catch (error) {
    logger.error('Error in load balancing:', error);
    res.status(500).json({
      success: false,
      error: 'Load balancing failed'
    });
  }
});

// Service discovery statistics
app.get('/stats', (req, res) => {
  try {
    const stats = serviceRegistry.getStatistics();
    
    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Error fetching statistics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch statistics'
    });
  }
});

// Error handling
app.use(notFound);
app.use(errorHandler);

// Initialize and start the server
const startServer = async () => {
  try {
    // Initialize with default services
    await serviceRegistry.initializeWithDefaults(discoveryConfig.defaultServices);
    
    // Start health monitoring
    healthMonitor.start();
    
    app.listen(PORT, () => {
      logger.info(\`Service Discovery running on port \${PORT}\`);
      logger.info(\`Environment: \${discoveryConfig.server.environment}\`);
      
      const services = serviceRegistry.getAllServices();
      logger.info(\`Registered \${services.length} services\`);
    });
  } catch (error) {
    logger.error('Failed to start Service Discovery:', error);
    process.exit(1);
  }
};

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  healthMonitor.stop();
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  healthMonitor.stop();
  process.exit(0);
});

startServer();

module.exports = app;
` : `import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import { createLogger, requestLogger } from '../../shared/utils/logger.js';
import { errorHandler, notFound } from '../../shared/middlewares/error.js';
import discoveryConfig from './config/discovery.js';
import { ServiceRegistry } from './services/ServiceRegistry.js';
import { HealthMonitor } from './services/HealthMonitor.js';
import { LoadBalancer } from './services/LoadBalancer.js';
import 'dotenv/config';

const app = express();
const PORT = discoveryConfig.server.port;
const logger = createLogger('service-discovery');

const serviceRegistry = new ServiceRegistry();
const healthMonitor = new HealthMonitor(serviceRegistry, discoveryConfig);
const loadBalancer = new LoadBalancer(serviceRegistry, discoveryConfig);

const rateLimiter = new RateLimiterMemory({
  keyGenerator: (req) => req.ip,
  points: 1000,
  duration: 60,
  blockDuration: 60 * 5
});

app.use(helmet());
app.use(compression());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger('service-discovery'));

app.use(async (req, res, next) => {
  try {
    await rateLimiter.consume(req.ip);
    next();
  } catch (rejRes) {
    res.status(429).json({
      success: false,
      error: 'Too many requests from this IP, please try again later'
    });
  }
});

const authenticateService = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or missing API key'
    });
  }
  
  next();
};

app.get('/health', (req, res) => {
  const registryStatus = serviceRegistry.getStatus();
  
  res.json({
    success: true,
    message: 'Service Discovery is healthy',
    timestamp: new Date().toISOString(),
    registry: registryStatus
  });
});

app.get('/services', (req, res) => {
  try {
    const services = serviceRegistry.getAllServices();
    
    res.json({
      success: true,
      data: {
        services,
        total: services.length,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    logger.error('Error fetching services:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch services'
    });
  }
});

app.get('/services/:serviceName', (req, res) => {
  try {
    const { serviceName } = req.params;
    const service = serviceRegistry.getService(serviceName);
    
    if (!service) {
      return res.status(404).json({
        success: false,
        error: \`Service '\${serviceName}' not found\`
      });
    }
    
    res.json({
      success: true,
      data: service
    });
  } catch (error) {
    logger.error('Error fetching service:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch service'
    });
  }
});

app.get('/services/:serviceName/healthy', (req, res) => {
  try {
    const { serviceName } = req.params;
    const healthyInstances = serviceRegistry.getHealthyInstances(serviceName);
    
    if (healthyInstances.length === 0) {
      return res.status(404).json({
        success: false,
        error: \`No healthy instances found for service '\${serviceName}'\`
      });
    }
    
    res.json({
      success: true,
      data: {
        service: serviceName,
        instances: healthyInstances,
        count: healthyInstances.length
      }
    });
  } catch (error) {
    logger.error('Error fetching healthy instances:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch healthy instances'
    });
  }
});

app.post('/register', authenticateService, (req, res) => {
  try {
    const serviceData = req.body;
    
    if (!serviceData.name || !serviceData.url) {
      return res.status(400).json({
        success: false,
        error: 'Service name and URL are required'
      });
    }
    
    const registeredService = serviceRegistry.registerService(serviceData);
    
    logger.info(\`Service registered: \${serviceData.name} at \${serviceData.url}\`);
    
    res.status(201).json({
      success: true,
      message: \`Service '\${serviceData.name}' registered successfully\`,
      data: registeredService
    });
  } catch (error) {
    logger.error('Error registering service:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to register service'
    });
  }
});

app.post('/heartbeat', authenticateService, (req, res) => {
  try {
    const { serviceName, instanceId } = req.body;
    
    if (!serviceName || !instanceId) {
      return res.status(400).json({
        success: false,
        error: 'Service name and instance ID are required'
      });
    }
    
    const updated = serviceRegistry.updateHeartbeat(serviceName, instanceId);
    
    if (!updated) {
      return res.status(404).json({
        success: false,
        error: \`Service '\${serviceName}' with instance '\${instanceId}' not found\`
      });
    }
    
    res.json({
      success: true,
      message: 'Heartbeat received'
    });
  } catch (error) {
    logger.error('Error processing heartbeat:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process heartbeat'
    });
  }
});

app.post('/unregister', authenticateService, (req, res) => {
  try {
    const { serviceName, instanceId } = req.body;
    
    if (!serviceName || !instanceId) {
      return res.status(400).json({
        success: false,
        error: 'Service name and instance ID are required'
      });
    }
    
    const unregistered = serviceRegistry.unregisterService(serviceName, instanceId);
    
    if (!unregistered) {
      return res.status(404).json({
        success: false,
        error: \`Service '\${serviceName}' with instance '\${instanceId}' not found\`
      });
    }
    
    logger.info(\`Service unregistered: \${serviceName} instance \${instanceId}\`);
    
    res.json({
      success: true,
      message: \`Service '\${serviceName}' unregistered successfully\`
    });
  } catch (error) {
    logger.error('Error unregistering service:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to unregister service'
    });
  }
});

app.get('/balance/:serviceName', (req, res) => {
  try {
    const { serviceName } = req.params;
    const instance = loadBalancer.getNextInstance(serviceName);
    
    if (!instance) {
      return res.status(404).json({
        success: false,
        error: \`No available instances for service '\${serviceName}'\`
      });
    }
    
    res.json({
      success: true,
      data: instance
    });
  } catch (error) {
    logger.error('Error in load balancing:', error);
    res.status(500).json({
      success: false,
      error: 'Load balancing failed'
    });
  }
});

app.get('/stats', (req, res) => {
  try {
    const stats = serviceRegistry.getStatistics();
    
    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Error fetching statistics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch statistics'
    });
  }
});

app.use(notFound);
app.use(errorHandler);

const startServer = async () => {
  try {
    await serviceRegistry.initializeWithDefaults(discoveryConfig.defaultServices);
    healthMonitor.start();
    
    app.listen(PORT, () => {
      logger.info(\`Service Discovery running on port \${PORT}\`);
      logger.info(\`Environment: \${discoveryConfig.server.environment}\`);
      
      const services = serviceRegistry.getAllServices();
      logger.info(\`Registered \${services.length} services\`);
    });
  } catch (error) {
    logger.error('Failed to start Service Discovery:', error);
    process.exit(1);
  }
};

process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  healthMonitor.stop();
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  healthMonitor.stop();
  process.exit(0);
});

startServer();

export default app;
`;

  await fs.writeFile(
    path.join(discoveryPath, `src/server.${ext}`),
    serverContent
  );
}

async generateDiscoveryService() {
  const discoveryPath = path.join(this.projectPath, 'service-discovery');
  const ext = 'js';
  const isCJS = this.config.moduleType === 'cjs';

  // Service Registry
  const serviceRegistry = isCJS ? `const { createLogger } = require('../../../shared/utils/logger');
const { redis } = require('../../../shared/config/redis');

const logger = createLogger('service-registry');

class ServiceRegistry {
  constructor() {
    this.services = new Map();
    this.redis = redis;
    this.redisKey = 'service_registry';
  }

  // Initialize with default services
  async initializeWithDefaults(defaultServices) {
    try {
      for (const [serviceName, serviceConfig] of Object.entries(defaultServices)) {
        await this.registerService({
          ...serviceConfig,
          instanceId: \`\${serviceName}-default-1\`,
          status: 'unknown',
          lastHeartbeat: new Date(),
          metadata: {
            ...serviceConfig.metadata,
            isDefault: true
          }
        });
      }
      
      logger.info(\`Initialized with \${Object.keys(defaultServices).length} default services\`);
    } catch (error) {
      logger.error('Error initializing default services:', error);
      throw error;
    }
  }

  // Register a new service instance
  async registerService(serviceData) {
    const {
      name,
      url,
      instanceId = \`\${name}-\${Date.now()}\`,
      version = '1.0.0',
      endpoints = [],
      healthCheck = '/health',
      metadata = {}
    } = serviceData;

    const serviceInstance = {
      instanceId,
      name,
      url,
      version,
      endpoints,
      healthCheck,
      status: 'healthy',
      lastHeartbeat: new Date(),
      registeredAt: new Date(),
      failureCount: 0,
      metadata
    };

    // Store in memory
    if (!this.services.has(name)) {
      this.services.set(name, new Map());
    }
    this.services.get(name).set(instanceId, serviceInstance);

    // Store in Redis for persistence
    await this.persistToRedis();

    logger.info(\`Service registered: \${name} (\${instanceId}) at \${url}\`);

    return serviceInstance;
  }

  // Unregister a service instance
  async unregisterService(serviceName, instanceId) {
    if (!this.services.has(serviceName)) {
      return false;
    }

    const serviceInstances = this.services.get(serviceName);
    const unregistered = serviceInstances.delete(instanceId);

    if (serviceInstances.size === 0) {
      this.services.delete(serviceName);
    }

    if (unregistered) {
      await this.persistToRedis();
      logger.info(\`Service unregistered: \${serviceName} (\${instanceId})\`);
    }

    return unregistered;
  }

  // Update service heartbeat
  async updateHeartbeat(serviceName, instanceId) {
    if (!this.services.has(serviceName)) {
      return false;
    }

    const serviceInstances = this.services.get(serviceName);
    const serviceInstance = serviceInstances.get(instanceId);

    if (!serviceInstance) {
      return false;
    }

    serviceInstance.lastHeartbeat = new Date();
    serviceInstance.failureCount = 0; // Reset failure count on successful heartbeat

    if (serviceInstance.status !== 'healthy') {
      serviceInstance.status = 'healthy';
      logger.info(\`Service \${serviceName} (\${instanceId}) marked as healthy\`);
    }

    await this.persistToRedis();

    return true;
  }

  // Mark service as unhealthy
  async markUnhealthy(serviceName, instanceId) {
    if (!this.services.has(serviceName)) {
      return false;
    }

    const serviceInstances = this.services.get(serviceName);
    const serviceInstance = serviceInstances.get(instanceId);

    if (!serviceInstance) {
      return false;
    }

    serviceInstance.failureCount += 1;
    serviceInstance.status = 'unhealthy';

    logger.warn(\`Service \${serviceName} (\${instanceId}) marked as unhealthy. Failure count: \${serviceInstance.failureCount}\`);

    await this.persistToRedis();

    return true;
  }

  // Get all services
  getAllServices() {
    const allServices = [];
    
    for (const [serviceName, instances] of this.services) {
      for (const [instanceId, instance] of instances) {
        allServices.push({
          service: serviceName,
          instance: instanceId,
          ...instance
        });
      }
    }
    
    return allServices;
  }

  // Get service by name
  getService(serviceName) {
    if (!this.services.has(serviceName)) {
      return null;
    }

    const instances = Array.from(this.services.get(serviceName).values());
    return {
      name: serviceName,
      instances,
      totalInstances: instances.length,
      healthyInstances: instances.filter(inst => inst.status === 'healthy').length
    };
  }

  // Get healthy instances of a service
  getHealthyInstances(serviceName) {
    if (!this.services.has(serviceName)) {
      return [];
    }

    const instances = Array.from(this.services.get(serviceName).values());
    return instances.filter(instance => 
      instance.status === 'healthy' && 
      this.isInstanceAlive(instance)
    );
  }

  // Check if instance is alive based on last heartbeat
  isInstanceAlive(instance) {
    const now = new Date();
    const lastHeartbeat = new Date(instance.lastHeartbeat);
    const timeSinceLastHeartbeat = now - lastHeartbeat;
    
    return timeSinceLastHeartbeat < (process.env.SERVICE_TTL || 60000); // Default 1 minute TTL
  }

  // Clean up dead services
  async cleanupDeadServices() {
    const now = new Date();
    let cleanedCount = 0;

    for (const [serviceName, instances] of this.services) {
      for (const [instanceId, instance] of instances) {
        if (!this.isInstanceAlive(instance)) {
          instances.delete(instanceId);
          cleanedCount++;
          logger.info(\`Cleaned up dead service: \${serviceName} (\${instanceId})\`);
        }
      }

      if (instances.size === 0) {
        this.services.delete(serviceName);
      }
    }

    if (cleanedCount > 0) {
      await this.persistToRedis();
      logger.info(\`Cleaned up \${cleanedCount} dead service instances\`);
    }

    return cleanedCount;
  }

  // Get registry status
  getStatus() {
    const totalServices = this.services.size;
    let totalInstances = 0;
    let healthyInstances = 0;

    for (const instances of this.services.values()) {
      totalInstances += instances.size;
      healthyInstances += Array.from(instances.values()).filter(inst => 
        inst.status === 'healthy' && this.isInstanceAlive(inst)
      ).length;
    }

    return {
      totalServices,
      totalInstances,
      healthyInstances,
      unhealthyInstances: totalInstances - healthyInstances,
      lastUpdated: new Date().toISOString()
    };
  }

  // Get statistics
  getStatistics() {
    const status = this.getStatus();
    const serviceStats = {};

    for (const [serviceName, instances] of this.services) {
      const healthy = Array.from(instances.values()).filter(inst => 
        inst.status === 'healthy' && this.isInstanceAlive(inst)
      ).length;
      
      serviceStats[serviceName] = {
        totalInstances: instances.size,
        healthyInstances: healthy,
        unhealthyInstances: instances.size - healthy
      };
    }

    return {
      ...status,
      services: serviceStats
    };
  }

  // Persist to Redis
  async persistToRedis() {
    try {
      const servicesData = {};
      
      for (const [serviceName, instances] of this.services) {
        servicesData[serviceName] = Object.fromEntries(instances);
      }
      
      await this.redis.set(this.redisKey, JSON.stringify(servicesData));
    } catch (error) {
      logger.error('Error persisting to Redis:', error);
    }
  }

  // Load from Redis
  async loadFromRedis() {
    try {
      const servicesData = await this.redis.get(this.redisKey);
      
      if (servicesData) {
        const parsedData = JSON.parse(servicesData);
        
        for (const [serviceName, instances] of Object.entries(parsedData)) {
          this.services.set(serviceName, new Map(Object.entries(instances)));
        }
        
        logger.info('Service registry loaded from Redis');
      }
    } catch (error) {
      logger.error('Error loading from Redis:', error);
    }
  }
}

module.exports = { ServiceRegistry };
` : `import { createLogger } from '../../../shared/utils/logger.js';
import { redis } from '../../../shared/config/redis.js';

const logger = createLogger('service-registry');

export class ServiceRegistry {
  constructor() {
    this.services = new Map();
    this.redis = redis;
    this.redisKey = 'service_registry';
  }

  async initializeWithDefaults(defaultServices) {
    try {
      for (const [serviceName, serviceConfig] of Object.entries(defaultServices)) {
        await this.registerService({
          ...serviceConfig,
          instanceId: \`\${serviceName}-default-1\`,
          status: 'unknown',
          lastHeartbeat: new Date(),
          metadata: {
            ...serviceConfig.metadata,
            isDefault: true
          }
        });
      }
      
      logger.info(\`Initialized with \${Object.keys(defaultServices).length} default services\`);
    } catch (error) {
      logger.error('Error initializing default services:', error);
      throw error;
    }
  }

  async registerService(serviceData) {
    const {
      name,
      url,
      instanceId = \`\${name}-\${Date.now()}\`,
      version = '1.0.0',
      endpoints = [],
      healthCheck = '/health',
      metadata = {}
    } = serviceData;

    const serviceInstance = {
      instanceId,
      name,
      url,
      version,
      endpoints,
      healthCheck,
      status: 'healthy',
      lastHeartbeat: new Date(),
      registeredAt: new Date(),
      failureCount: 0,
      metadata
    };

    if (!this.services.has(name)) {
      this.services.set(name, new Map());
    }
    this.services.get(name).set(instanceId, serviceInstance);

    await this.persistToRedis();

    logger.info(\`Service registered: \${name} (\${instanceId}) at \${url}\`);

    return serviceInstance;
  }

  async unregisterService(serviceName, instanceId) {
    if (!this.services.has(serviceName)) {
      return false;
    }

    const serviceInstances = this.services.get(serviceName);
    const unregistered = serviceInstances.delete(instanceId);

    if (serviceInstances.size === 0) {
      this.services.delete(serviceName);
    }

    if (unregistered) {
      await this.persistToRedis();
      logger.info(\`Service unregistered: \${serviceName} (\${instanceId})\`);
    }

    return unregistered;
  }

  async updateHeartbeat(serviceName, instanceId) {
    if (!this.services.has(serviceName)) {
      return false;
    }

    const serviceInstances = this.services.get(serviceName);
    const serviceInstance = serviceInstances.get(instanceId);

    if (!serviceInstance) {
      return false;
    }

    serviceInstance.lastHeartbeat = new Date();
    serviceInstance.failureCount = 0;

    if (serviceInstance.status !== 'healthy') {
      serviceInstance.status = 'healthy';
      logger.info(\`Service \${serviceName} (\${instanceId}) marked as healthy\`);
    }

    await this.persistToRedis();

    return true;
  }

  async markUnhealthy(serviceName, instanceId) {
    if (!this.services.has(serviceName)) {
      return false;
    }

    const serviceInstances = this.services.get(serviceName);
    const serviceInstance = serviceInstances.get(instanceId);

    if (!serviceInstance) {
      return false;
    }

    serviceInstance.failureCount += 1;
    serviceInstance.status = 'unhealthy';

    logger.warn(\`Service \${serviceName} (\${instanceId}) marked as unhealthy. Failure count: \${serviceInstance.failureCount}\`);

    await this.persistToRedis();

    return true;
  }

  getAllServices() {
    const allServices = [];
    
    for (const [serviceName, instances] of this.services) {
      for (const [instanceId, instance] of instances) {
        allServices.push({
          service: serviceName,
          instance: instanceId,
          ...instance
        });
      }
    }
    
    return allServices;
  }

  getService(serviceName) {
    if (!this.services.has(serviceName)) {
      return null;
    }

    const instances = Array.from(this.services.get(serviceName).values());
    return {
      name: serviceName,
      instances,
      totalInstances: instances.length,
      healthyInstances: instances.filter(inst => inst.status === 'healthy').length
    };
  }

  getHealthyInstances(serviceName) {
    if (!this.services.has(serviceName)) {
      return [];
    }

    const instances = Array.from(this.services.get(serviceName).values());
    return instances.filter(instance => 
      instance.status === 'healthy' && 
      this.isInstanceAlive(instance)
    );
  }

  isInstanceAlive(instance) {
    const now = new Date();
    const lastHeartbeat = new Date(instance.lastHeartbeat);
    const timeSinceLastHeartbeat = now - lastHeartbeat;
    
    return timeSinceLastHeartbeat < (process.env.SERVICE_TTL || 60000);
  }

  async cleanupDeadServices() {
    const now = new Date();
    let cleanedCount = 0;

    for (const [serviceName, instances] of this.services) {
      for (const [instanceId, instance] of instances) {
        if (!this.isInstanceAlive(instance)) {
          instances.delete(instanceId);
          cleanedCount++;
          logger.info(\`Cleaned up dead service: \${serviceName} (\${instanceId})\`);
        }
      }

      if (instances.size === 0) {
        this.services.delete(serviceName);
      }
    }

    if (cleanedCount > 0) {
      await this.persistToRedis();
      logger.info(\`Cleaned up \${cleanedCount} dead service instances\`);
    }

    return cleanedCount;
  }

  getStatus() {
    const totalServices = this.services.size;
    let totalInstances = 0;
    let healthyInstances = 0;

    for (const instances of this.services.values()) {
      totalInstances += instances.size;
      healthyInstances += Array.from(instances.values()).filter(inst => 
        inst.status === 'healthy' && this.isInstanceAlive(inst)
      ).length;
    }

    return {
      totalServices,
      totalInstances,
      healthyInstances,
      unhealthyInstances: totalInstances - healthyInstances,
      lastUpdated: new Date().toISOString()
    };
  }

  getStatistics() {
    const status = this.getStatus();
    const serviceStats = {};

    for (const [serviceName, instances] of this.services) {
      const healthy = Array.from(instances.values()).filter(inst => 
        inst.status === 'healthy' && this.isInstanceAlive(inst)
      ).length;
      
      serviceStats[serviceName] = {
        totalInstances: instances.size,
        healthyInstances: healthy,
        unhealthyInstances: instances.size - healthy
      };
    }

    return {
      ...status,
      services: serviceStats
    };
  }

  async persistToRedis() {
    try {
      const servicesData = {};
      
      for (const [serviceName, instances] of this.services) {
        servicesData[serviceName] = Object.fromEntries(instances);
      }
      
      await this.redis.set(this.redisKey, JSON.stringify(servicesData));
    } catch (error) {
      logger.error('Error persisting to Redis:', error);
    }
  }

  async loadFromRedis() {
    try {
      const servicesData = await this.redis.get(this.redisKey);
      
      if (servicesData) {
        const parsedData = JSON.parse(servicesData);
        
        for (const [serviceName, instances] of Object.entries(parsedData)) {
          this.services.set(serviceName, new Map(Object.entries(instances)));
        }
        
        logger.info('Service registry loaded from Redis');
      }
    } catch (error) {
      logger.error('Error loading from Redis:', error);
    }
  }
}
`;

  await fs.writeFile(
    path.join(discoveryPath, `src/services/ServiceRegistry.${ext}`),
    serviceRegistry
  );

  // Health Monitor Service
  const healthMonitor = isCJS ? `const { createLogger } = require('../../../shared/utils/logger');
const axios = require('axios');

const logger = createLogger('health-monitor');

class HealthMonitor {
  constructor(serviceRegistry, config) {
    this.serviceRegistry = serviceRegistry;
    this.config = config;
    this.healthCheckInterval = null;
    this.isRunning = false;
  }

  // Start health monitoring
  start() {
    if (this.isRunning) {
      logger.warn('Health monitor is already running');
      return;
    }

    this.isRunning = true;
    this.healthCheckInterval = setInterval(() => {
      this.performHealthChecks();
    }, this.config.registry.healthCheckInterval);

    logger.info('Health monitor started');
  }

  // Stop health monitoring
  stop() {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
    this.isRunning = false;
    logger.info('Health monitor stopped');
  }

  // Perform health checks for all services
  async performHealthChecks() {
    const services = this.serviceRegistry.getAllServices();
    
    if (services.length === 0) {
      return;
    }

    logger.debug(\`Performing health checks for \${services.length} service instances\`);

    const healthCheckPromises = services.map(service => 
      this.checkServiceHealth(service)
    );

    await Promise.allSettled(healthCheckPromises);

    // Clean up dead services
    await this.serviceRegistry.cleanupDeadServices();
  }

  // Check health of a specific service instance
  async checkServiceHealth(serviceInstance) {
    const { name, instanceId, url, healthCheck } = serviceInstance;

    try {
      const healthCheckUrl = \`\${url}\${healthCheck}\`;
      
      const response = await axios.get(healthCheckUrl, {
        timeout: this.config.registry.healthCheckTimeout
      });

      if (response.status === 200 && response.data.success) {
        // Service is healthy
        await this.serviceRegistry.updateHeartbeat(name, instanceId);
        
        if (process.env.LOG_SERVICES_HEALTH === 'true') {
          logger.debug(\`Health check passed: \${name} (\${instanceId})\`);
        }
      } else {
        // Service responded but with error status
        await this.handleServiceFailure(name, instanceId, \`Health check returned status \${response.status}\`);
      }
    } catch (error) {
      // Service is unreachable or timed out
      await this.handleServiceFailure(name, instanceId, error.message);
    }
  }

  // Handle service failure
  async handleServiceFailure(serviceName, instanceId, errorMessage) {
    await this.serviceRegistry.markUnhealthy(serviceName, instanceId);
    
    const service = this.serviceRegistry.getService(serviceName);
    const instance = service?.instances.find(inst => inst.instanceId === instanceId);
    
    if (instance && instance.failureCount >= this.config.registry.maxFailures) {
      logger.error(
        \`Service \${serviceName} (\${instanceId}) has exceeded failure threshold. \` +
        \`Failures: \${instance.failureCount}. Last error: \${errorMessage}\`
      );
      
      // Here you could implement circuit breaker pattern
      // or notify administrators about critical service failures
    } else {
      logger.warn(
        \`Health check failed for \${serviceName} (\${instanceId}): \${errorMessage}\`
      );
    }
  }

  // Get health monitor status
  getStatus() {
    return {
      isRunning: this.isRunning,
      lastCheck: new Date().toISOString(),
      config: {
        healthCheckInterval: this.config.registry.healthCheckInterval,
        healthCheckTimeout: this.config.registry.healthCheckTimeout,
        maxFailures: this.config.registry.maxFailures
      }
    };
  }
}

module.exports = { HealthMonitor };
` : `import { createLogger } from '../../../shared/utils/logger.js';
import axios from 'axios';

const logger = createLogger('health-monitor');

export class HealthMonitor {
  constructor(serviceRegistry, config) {
    this.serviceRegistry = serviceRegistry;
    this.config = config;
    this.healthCheckInterval = null;
    this.isRunning = false;
  }

  start() {
    if (this.isRunning) {
      logger.warn('Health monitor is already running');
      return;
    }

    this.isRunning = true;
    this.healthCheckInterval = setInterval(() => {
      this.performHealthChecks();
    }, this.config.registry.healthCheckInterval);

    logger.info('Health monitor started');
  }

  stop() {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
    this.isRunning = false;
    logger.info('Health monitor stopped');
  }

  async performHealthChecks() {
    const services = this.serviceRegistry.getAllServices();
    
    if (services.length === 0) {
      return;
    }

    logger.debug(\`Performing health checks for \${services.length} service instances\`);

    const healthCheckPromises = services.map(service => 
      this.checkServiceHealth(service)
    );

    await Promise.allSettled(healthCheckPromises);

    await this.serviceRegistry.cleanupDeadServices();
  }

  async checkServiceHealth(serviceInstance) {
    const { name, instanceId, url, healthCheck } = serviceInstance;

    try {
      const healthCheckUrl = \`\${url}\${healthCheck}\`;
      
      const response = await axios.get(healthCheckUrl, {
        timeout: this.config.registry.healthCheckTimeout
      });

      if (response.status === 200 && response.data.success) {
        await this.serviceRegistry.updateHeartbeat(name, instanceId);
        
        if (process.env.LOG_SERVICES_HEALTH === 'true') {
          logger.debug(\`Health check passed: \${name} (\${instanceId})\`);
        }
      } else {
        await this.handleServiceFailure(name, instanceId, \`Health check returned status \${response.status}\`);
      }
    } catch (error) {
      await this.handleServiceFailure(name, instanceId, error.message);
    }
  }

  async handleServiceFailure(serviceName, instanceId, errorMessage) {
    await this.serviceRegistry.markUnhealthy(serviceName, instanceId);
    
    const service = this.serviceRegistry.getService(serviceName);
    const instance = service?.instances.find(inst => inst.instanceId === instanceId);
    
    if (instance && instance.failureCount >= this.config.registry.maxFailures) {
      logger.error(
        \`Service \${serviceName} (\${instanceId}) has exceeded failure threshold. \` +
        \`Failures: \${instance.failureCount}. Last error: \${errorMessage}\`
      );
    } else {
      logger.warn(
        \`Health check failed for \${serviceName} (\${instanceId}): \${errorMessage}\`
      );
    }
  }

  getStatus() {
    return {
      isRunning: this.isRunning,
      lastCheck: new Date().toISOString(),
      config: {
        healthCheckInterval: this.config.registry.healthCheckInterval,
        healthCheckTimeout: this.config.registry.healthCheckTimeout,
        maxFailures: this.config.registry.maxFailures
      }
    };
  }
}
`;

  await fs.writeFile(
    path.join(discoveryPath, `src/services/HealthMonitor.${ext}`),
    healthMonitor
  );

  // Load Balancer Service
  const loadBalancer = isCJS ? `const { createLogger } = require('../../../shared/utils/logger');

const logger = createLogger('load-balancer');

class LoadBalancer {
  constructor(serviceRegistry, config) {
    this.serviceRegistry = serviceRegistry;
    this.config = config.loadBalancing;
    this.currentIndexes = new Map(); // For round-robin strategy
    this.connectionCounts = new Map(); // For least-connections strategy
  }

  // Get next available instance for a service
  getNextInstance(serviceName) {
    const healthyInstances = this.serviceRegistry.getHealthyInstances(serviceName);
    
    if (healthyInstances.length === 0) {
      return null;
    }

    switch (this.config.strategy) {
      case 'round-robin':
        return this.roundRobin(serviceName, healthyInstances);
      
      case 'least-connections':
        return this.leastConnections(serviceName, healthyInstances);
      
      case 'random':
        return this.random(healthyInstances);
      
      default:
        return this.roundRobin(serviceName, healthyInstances);
    }
  }

  // Round-robin load balancing strategy
  roundRobin(serviceName, instances) {
    if (!this.currentIndexes.has(serviceName)) {
      this.currentIndexes.set(serviceName, 0);
    }

    const currentIndex = this.currentIndexes.get(serviceName);
    const instance = instances[currentIndex];
    
    // Update index for next request
    const nextIndex = (currentIndex + 1) % instances.length;
    this.currentIndexes.set(serviceName, nextIndex);

    logger.debug(\`Round-robin: Selected \${serviceName} instance \${instance.instanceId} (index \${currentIndex})\`);

    return instance;
  }

  // Least-connections load balancing strategy
  leastConnections(serviceName, instances) {
    // Initialize connection counts if not present
    instances.forEach(instance => {
      if (!this.connectionCounts.has(instance.instanceId)) {
        this.connectionCounts.set(instance.instanceId, 0);
      }
    });

    // Find instance with least connections
    let minConnections = Infinity;
    let selectedInstance = null;

    for (const instance of instances) {
      const connections = this.connectionCounts.get(instance.instanceId) || 0;
      
      if (connections < minConnections) {
        minConnections = connections;
        selectedInstance = instance;
      }
    }

    if (selectedInstance) {
      // Increment connection count for selected instance
      const currentCount = this.connectionCounts.get(selectedInstance.instanceId) || 0;
      this.connectionCounts.set(selectedInstance.instanceId, currentCount + 1);

      logger.debug(\`Least-connections: Selected \${serviceName} instance \${selectedInstance.instanceId} (\${currentCount + 1} connections)\`);
    }

    return selectedInstance;
  }

  // Random load balancing strategy
  random(instances) {
    const randomIndex = Math.floor(Math.random() * instances.length);
    const instance = instances[randomIndex];

    logger.debug(\`Random: Selected instance \${instance.instanceId} (index \${randomIndex})\`);

    return instance;
  }

  // Release a connection (for least-connections strategy)
  releaseConnection(instanceId) {
    if (this.connectionCounts.has(instanceId)) {
      const currentCount = this.connectionCounts.get(instanceId);
      if (currentCount > 0) {
        this.connectionCounts.set(instanceId, currentCount - 1);
      }
    }
  }

  // Get load balancer statistics
  getStatistics() {
    return {
      strategy: this.config.strategy,
      currentIndexes: Object.fromEntries(this.currentIndexes),
      connectionCounts: Object.fromEntries(this.connectionCounts),
      stickySessions: this.config.stickySessions
    };
  }

  // Update load balancing strategy
  updateStrategy(newStrategy) {
    const validStrategies = ['round-robin', 'least-connections', 'random'];
    
    if (validStrategies.includes(newStrategy)) {
      this.config.strategy = newStrategy;
      logger.info(\`Load balancing strategy updated to: \${newStrategy}\`);
    } else {
      throw new Error(\`Invalid load balancing strategy: \${newStrategy}\`);
    }
  }
}

module.exports = { LoadBalancer };
` : `import { createLogger } from '../../../shared/utils/logger.js';

const logger = createLogger('load-balancer');

export class LoadBalancer {
  constructor(serviceRegistry, config) {
    this.serviceRegistry = serviceRegistry;
    this.config = config.loadBalancing;
    this.currentIndexes = new Map();
    this.connectionCounts = new Map();
  }

  getNextInstance(serviceName) {
    const healthyInstances = this.serviceRegistry.getHealthyInstances(serviceName);
    
    if (healthyInstances.length === 0) {
      return null;
    }

    switch (this.config.strategy) {
      case 'round-robin':
        return this.roundRobin(serviceName, healthyInstances);
      
      case 'least-connections':
        return this.leastConnections(serviceName, healthyInstances);
      
      case 'random':
        return this.random(healthyInstances);
      
      default:
        return this.roundRobin(serviceName, healthyInstances);
    }
  }

  roundRobin(serviceName, instances) {
    if (!this.currentIndexes.has(serviceName)) {
      this.currentIndexes.set(serviceName, 0);
    }

    const currentIndex = this.currentIndexes.get(serviceName);
    const instance = instances[currentIndex];
    
    const nextIndex = (currentIndex + 1) % instances.length;
    this.currentIndexes.set(serviceName, nextIndex);

    logger.debug(\`Round-robin: Selected \${serviceName} instance \${instance.instanceId} (index \${currentIndex})\`);

    return instance;
  }

  leastConnections(serviceName, instances) {
    instances.forEach(instance => {
      if (!this.connectionCounts.has(instance.instanceId)) {
        this.connectionCounts.set(instance.instanceId, 0);
      }
    });

    let minConnections = Infinity;
    let selectedInstance = null;

    for (const instance of instances) {
      const connections = this.connectionCounts.get(instance.instanceId) || 0;
      
      if (connections < minConnections) {
        minConnections = connections;
        selectedInstance = instance;
      }
    }

    if (selectedInstance) {
      const currentCount = this.connectionCounts.get(selectedInstance.instanceId) || 0;
      this.connectionCounts.set(selectedInstance.instanceId, currentCount + 1);

      logger.debug(\`Least-connections: Selected \${serviceName} instance \${selectedInstance.instanceId} (\${currentCount + 1} connections)\`);
    }

    return selectedInstance;
  }

  random(instances) {
    const randomIndex = Math.floor(Math.random() * instances.length);
    const instance = instances[randomIndex];

    logger.debug(\`Random: Selected instance \${instance.instanceId} (index \${randomIndex})\`);

    return instance;
  }

  releaseConnection(instanceId) {
    if (this.connectionCounts.has(instanceId)) {
      const currentCount = this.connectionCounts.get(instanceId);
      if (currentCount > 0) {
        this.connectionCounts.set(instanceId, currentCount - 1);
      }
    }
  }

  getStatistics() {
    return {
      strategy: this.config.strategy,
      currentIndexes: Object.fromEntries(this.currentIndexes),
      connectionCounts: Object.fromEntries(this.connectionCounts),
      stickySessions: this.config.stickySessions
    };
  }

  updateStrategy(newStrategy) {
    const validStrategies = ['round-robin', 'least-connections', 'random'];
    
    if (validStrategies.includes(newStrategy)) {
      this.config.strategy = newStrategy;
      logger.info(\`Load balancing strategy updated to: \${newStrategy}\`);
    } else {
      throw new Error(\`Invalid load balancing strategy: \${newStrategy}\`);
    }
  }
}
`;

  await fs.writeFile(
    path.join(discoveryPath, `src/services/LoadBalancer.${ext}`),
    loadBalancer
  );
}

async generateDiscoveryPackageJson() {
  const discoveryPath = path.join(this.projectPath, 'service-discovery');
  const ext = this.config.moduleType === 'cjs' ? 'cjs' : 'js';
  const isCJS = this.config.moduleType === 'cjs';
  
  const packageJson = {
    name: 'service-discovery',
    version: '1.0.0',
    description: 'Service Discovery for microservices architecture',
    main: `src/server.${ext}`,
    type: isCJS ? 'commonjs' : 'module',
    scripts: {
      start: `node src/server.${ext}`,
      dev: `nodemon src/server.${ext}`,
      test: 'jest',
      'test:watch': 'jest --watch'
    },
    dependencies: {
      express: '^4.18.0',
      'dotenv': '^16.0.0',
      'cors': '^2.8.5',
      'helmet': '^7.0.0',
      'compression': '^1.7.0',
      'rate-limiter-flexible': '^3.0.0',
      'winston': '^3.8.0',
      'redis': '^4.0.0',
      'axios': '^1.4.0'
    },
    devDependencies: {
      nodemon: '^2.0.0',
      jest: '^29.0.0',
      supertest: '^6.0.0'
    }
  };

  await fs.writeJson(path.join(discoveryPath, 'package.json'), packageJson, { spaces: 2 });
}
  javascript
async generateDockerSetup() {
  const dockerPath = path.join(this.projectPath, 'docker');
  
  // Create docker directory structure
  const dockerDirs = [
    'configs',
    'scripts',
    'volumes',
    'logs'
  ];

  for (const dir of dockerDirs) {
    await this.ensureDirectory(path.join(dockerPath, dir));
  }

  // Generate docker-compose for microservices
  await this.generateDockerCompose();
  
  // Generate individual service Dockerfiles - FIXED: Pass the correct servicePath
  for (const service of this.config.microservices.services) {
    const servicePath = path.join(this.projectPath, `services/${service}-service`);
    await this.generateServiceDockerfile(service, servicePath);
  }

  // Generate Docker-related configuration files
  await this.generateDockerEnv();
  await this.generateDockerScripts();
}

async generateDockerSetup() {
  const dockerPath = path.join(this.projectPath, 'docker');
  
  // Create docker directory structure
  const dockerDirs = [
    'configs',
    'scripts',
    'volumes',
    'logs'
  ];

  for (const dir of dockerDirs) {
    await this.ensureDirectory(path.join(dockerPath, dir));
  }

  // Generate docker-compose for microservices
  await this.generateDockerCompose();
  
  // Generate individual service Dockerfiles
  for (const service of this.config.microservices.services) {
    await this.generateServiceDockerfile(service);
  }

  // Generate Docker-related configuration files
  await this.generateDockerEnv();
  await this.generateDockerScripts();
}

async generateDockerCompose() {
  const dockerPath = path.join(this.projectPath, 'docker');
  
  const dockerComposeContent = `version: '3.8'

services:
  # API Gateway
  api-gateway:
    build:
      context: ../api-gateway
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - API_GATEWAY_PORT=3000
      - JWT_ACCESS_SECRET=\${JWT_ACCESS_SECRET}
      - JWT_REFRESH_SECRET=\${JWT_REFRESH_SECRET}
      - JWT_SERVICE_SECRET=\${JWT_SERVICE_SECRET}
      - REDIS_URL=redis://redis:6379
    env_file:
      - .env
    depends_on:
      - redis
      - auth-service
      - user-service
      - notification-service
      - file-service
      - payment-service
      - analytics-service
    networks:
      - microservices-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Service Discovery
  service-discovery:
    build:
      context: ../service-discovery
      dockerfile: Dockerfile
    ports:
      - "8500:8500"
    environment:
      - NODE_ENV=production
      - SERVICE_DISCOVERY_PORT=8500
      - REDIS_URL=redis://redis:6379
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
    env_file:
      - .env
    depends_on:
      - redis
    networks:
      - microservices-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8500/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Auth Service
  auth-service:
    build:
      context: ../services/auth-service
      dockerfile: Dockerfile
    ports:
      - "3001:3001"
    environment:
      - NODE_ENV=production
      - PORT=3001
      - MONGODB_URI=mongodb://mongodb:27017/auth_service
      - REDIS_URL=redis://redis:6379
      - JWT_ACCESS_SECRET=\${JWT_ACCESS_SECRET}
      - JWT_REFRESH_SECRET=\${JWT_REFRESH_SECRET}
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
    env_file:
      - .env
    depends_on:
      - mongodb
      - redis
      - service-discovery
    networks:
      - microservices-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3001/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # User Service
  user-service:
    build:
      context: ../services/user-service
      dockerfile: Dockerfile
    ports:
      - "3002:3002"
    environment:
      - NODE_ENV=production
      - PORT=3002
      - MONGODB_URI=mongodb://mongodb:27017/user_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
    env_file:
      - .env
    depends_on:
      - mongodb
      - redis
      - service-discovery
    networks:
      - microservices-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3002/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Notification Service
  notification-service:
    build:
      context: ../services/notification-service
      dockerfile: Dockerfile
    ports:
      - "3003:3003"
    environment:
      - NODE_ENV=production
      - PORT=3003
      - MONGODB_URI=mongodb://mongodb:27017/notification_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
      - SMTP_HOST=\${SMTP_HOST}
      - SMTP_PORT=\${SMTP_PORT}
      - SMTP_USER=\${SMTP_USER}
      - SMTP_PASS=\${SMTP_PASS}
    env_file:
      - .env
    depends_on:
      - mongodb
      - redis
      - service-discovery
    networks:
      - microservices-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3003/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # File Service
  file-service:
    build:
      context: ../services/file-service
      dockerfile: Dockerfile
    ports:
      - "3004:3004"
    environment:
      - NODE_ENV=production
      - PORT=3004
      - MONGODB_URI=mongodb://mongodb:27017/file_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
      - UPLOAD_PATH=/app/uploads
    env_file:
      - .env
    depends_on:
      - mongodb
      - redis
      - service-discovery
    networks:
      - microservices-network
    volumes:
      - file_uploads:/app/uploads
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3004/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Payment Service
  payment-service:
    build:
      context: ../services/payment-service
      dockerfile: Dockerfile
    ports:
      - "3005:3005"
    environment:
      - NODE_ENV=production
      - PORT=3005
      - MONGODB_URI=mongodb://mongodb:27017/payment_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
      - STRIPE_SECRET_KEY=\${STRIPE_SECRET_KEY}
      - STRIPE_WEBHOOK_SECRET=\${STRIPE_WEBHOOK_SECRET}
    env_file:
      - .env
    depends_on:
      - mongodb
      - redis
      - service-discovery
    networks:
      - microservices-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3005/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Analytics Service
  analytics-service:
    build:
      context: ../services/analytics-service
      dockerfile: Dockerfile
    ports:
      - "3006:3006"
    environment:
      - NODE_ENV=production
      - PORT=3006
      - MONGODB_URI=mongodb://mongodb:27017/analytics_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
    env_file:
      - .env
    depends_on:
      - mongodb
      - redis
      - service-discovery
    networks:
      - microservices-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3006/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # MongoDB Database
  mongodb:
    image: mongo:7.0
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_ROOT_USERNAME=\${MONGO_ROOT_USERNAME}
      - MONGO_INITDB_ROOT_PASSWORD=\${MONGO_ROOT_PASSWORD}
    volumes:
      - mongodb_data:/data/db
      - ./configs/mongo-init.js:/docker-entrypoint-initdb.d/mongo-init.js:ro
    networks:
      - microservices-network
    restart: unless-stopped
    healthcheck:
      test: echo 'db.runCommand("ping").ok' | mongosh localhost:27017/test --quiet
      interval: 30s
      timeout: 10s
      retries: 3

  # Redis Cache & Message Queue
  redis:
    image: redis:7.2-alpine
    ports:
      - "6379:6379"
    command: redis-server --requirepass \${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
      - ./configs/redis.conf:/usr/local/etc/redis/redis.conf
    networks:
      - microservices-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Redis Commander (Web UI for Redis)
  redis-commander:
    image: rediscommander/redis-commander:latest
    ports:
      - "8081:8081"
    environment:
      - REDIS_HOSTS=local:redis:6379:\${REDIS_PASSWORD}
    depends_on:
      - redis
    networks:
      - microservices-network
    restart: unless-stopped

  # Mongo Express (Web UI for MongoDB)
  mongo-express:
    image: mongo-express:latest
    ports:
      - "8082:8081"
    environment:
      - ME_CONFIG_MONGODB_SERVER=mongodb
      - ME_CONFIG_MONGODB_PORT=27017
      - ME_CONFIG_MONGODB_ENABLE_ADMIN=true
      - ME_CONFIG_MONGODB_AUTH_DATABASE=admin
      - ME_CONFIG_MONGODB_AUTH_USERNAME=\${MONGO_ROOT_USERNAME}
      - ME_CONFIG_MONGODB_AUTH_PASSWORD=\${MONGO_ROOT_PASSWORD}
      - ME_CONFIG_BASICAUTH_USERNAME=\${MONGO_EXPRESS_USERNAME}
      - ME_CONFIG_BASICAUTH_PASSWORD=\${MONGO_EXPRESS_PASSWORD}
    depends_on:
      - mongodb
    networks:
      - microservices-network
    restart: unless-stopped

  # Nginx Load Balancer (Optional)
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./configs/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./configs/ssl:/etc/nginx/ssl:ro
    depends_on:
      - api-gateway
    networks:
      - microservices-network
    restart: unless-stopped

  # Traefik Reverse Proxy (Alternative to Nginx)
  traefik:
    image: traefik:v3.0
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./configs/traefik.yml:/etc/traefik/traefik.yml:ro
      - ./configs/ssl:/etc/traefik/ssl:ro
    networks:
      - microservices-network
    restart: unless-stopped

volumes:
  mongodb_data:
    driver: local
  redis_data:
    driver: local
  file_uploads:
    driver: local

networks:
  microservices-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
`;

  await fs.writeFile(
    path.join(dockerPath, 'docker-compose.yml'),
    dockerComposeContent
  );

  // Generate development docker-compose
  await this.generateDockerComposeDev();

  // Generate production docker-compose
  await this.generateDockerComposeProd();
}

async generateDockerComposeDev() {
  const dockerPath = path.join(this.projectPath, 'docker');
  
  const dockerComposeDevContent = `version: '3.8'

services:
  # API Gateway
  api-gateway:
    build:
      context: ../api-gateway
      dockerfile: Dockerfile.dev
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - API_GATEWAY_PORT=3000
      - JWT_ACCESS_SECRET=dev_jwt_access_secret
      - JWT_REFRESH_SECRET=dev_jwt_refresh_secret
      - JWT_SERVICE_SECRET=dev_jwt_service_secret
      - REDIS_URL=redis://redis:6379
    volumes:
      - ../api-gateway/src:/app/src
      - ../shared:/app/shared
    depends_on:
      - redis
    networks:
      - microservices-network
    restart: unless-stopped

  # Service Discovery
  service-discovery:
    build:
      context: ../service-discovery
      dockerfile: Dockerfile.dev
    ports:
      - "8500:8500"
    environment:
      - NODE_ENV=development
      - SERVICE_DISCOVERY_PORT=8500
      - REDIS_URL=redis://redis:6379
      - API_KEY=dev_service_discovery_key
    volumes:
      - ../service-discovery/src:/app/src
      - ../shared:/app/shared
    depends_on:
      - redis
    networks:
      - microservices-network
    restart: unless-stopped

  # Auth Service
  auth-service:
    build:
      context: ../services/auth-service
      dockerfile: Dockerfile.dev
    ports:
      - "3001:3001"
    environment:
      - NODE_ENV=development
      - PORT=3001
      - MONGODB_URI=mongodb://mongodb:27017/auth_service
      - REDIS_URL=redis://redis:6379
      - JWT_ACCESS_SECRET=dev_jwt_access_secret
      - JWT_REFRESH_SECRET=dev_jwt_refresh_secret
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=dev_service_discovery_key
    volumes:
      - ../services/auth-service/src:/app/src
      - ../shared:/app/shared
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices-network
    restart: unless-stopped

  # User Service
  user-service:
    build:
      context: ../services/user-service
      dockerfile: Dockerfile.dev
    ports:
      - "3002:3002"
    environment:
      - NODE_ENV=development
      - PORT=3002
      - MONGODB_URI=mongodb://mongodb:27017/user_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=dev_service_discovery_key
    volumes:
      - ../services/user-service/src:/app/src
      - ../shared:/app/shared
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices-network
    restart: unless-stopped

  # Notification Service
  notification-service:
    build:
      context: ../services/notification-service
      dockerfile: Dockerfile.dev
    ports:
      - "3003:3003"
    environment:
      - NODE_ENV=development
      - PORT=3003
      - MONGODB_URI=mongodb://mongodb:27017/notification_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=dev_service_discovery_key
    volumes:
      - ../services/notification-service/src:/app/src
      - ../shared:/app/shared
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices-network
    restart: unless-stopped

  # File Service
  file-service:
    build:
      context: ../services/file-service
      dockerfile: Dockerfile.dev
    ports:
      - "3004:3004"
    environment:
      - NODE_ENV=development
      - PORT=3004
      - MONGODB_URI=mongodb://mongodb:27017/file_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=dev_service_discovery_key
      - UPLOAD_PATH=/app/uploads
    volumes:
      - ../services/file-service/src:/app/src
      - ../shared:/app/shared
      - file_uploads:/app/uploads
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices-network
    restart: unless-stopped

  # Payment Service
  payment-service:
    build:
      context: ../services/payment-service
      dockerfile: Dockerfile.dev
    ports:
      - "3005:3005"
    environment:
      - NODE_ENV=development
      - PORT=3005
      - MONGODB_URI=mongodb://mongodb:27017/payment_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=dev_service_discovery_key
      - STRIPE_SECRET_KEY=sk_test_development_key
      - STRIPE_WEBHOOK_SECRET=whsec_development_secret
    volumes:
      - ../services/payment-service/src:/app/src
      - ../shared:/app/shared
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices-network
    restart: unless-stopped

  # Analytics Service
  analytics-service:
    build:
      context: ../services/analytics-service
      dockerfile: Dockerfile.dev
    ports:
      - "3006:3006"
    environment:
      - NODE_ENV=development
      - PORT=3006
      - MONGODB_URI=mongodb://mongodb:27017/analytics_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=dev_service_discovery_key
    volumes:
      - ../services/analytics-service/src:/app/src
      - ../shared:/app/shared
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices-network
    restart: unless-stopped

  # MongoDB Database
  mongodb:
    image: mongo:7.0
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=password
    volumes:
      - mongodb_data:/data/db
      - ./configs/mongo-init.js:/docker-entrypoint-initdb.d/mongo-init.js:ro
    networks:
      - microservices-network
    restart: unless-stopped

  # Redis Cache & Message Queue
  redis:
    image: redis:7.2-alpine
    ports:
      - "6379:6379"
    command: redis-server --requirepass password
    volumes:
      - redis_data:/data
    networks:
      - microservices-network
    restart: unless-stopped

  # Redis Commander (Web UI for Redis)
  redis-commander:
    image: rediscommander/redis-commander:latest
    ports:
      - "8081:8081"
    environment:
      - REDIS_HOSTS=local:redis:6379:password
    depends_on:
      - redis
    networks:
      - microservices-network
    restart: unless-stopped

  # Mongo Express (Web UI for MongoDB)
  mongo-express:
    image: mongo-express:latest
    ports:
      - "8082:8081"
    environment:
      - ME_CONFIG_MONGODB_SERVER=mongodb
      - ME_CONFIG_MONGODB_PORT=27017
      - ME_CONFIG_MONGODB_ENABLE_ADMIN=true
      - ME_CONFIG_MONGODB_AUTH_DATABASE=admin
      - ME_CONFIG_MONGODB_AUTH_USERNAME=admin
      - ME_CONFIG_MONGODB_AUTH_PASSWORD=password
      - ME_CONFIG_BASICAUTH_USERNAME=admin
      - ME_CONFIG_BASICAUTH_PASSWORD=password
    depends_on:
      - mongodb
    networks:
      - microservices-network
    restart: unless-stopped

volumes:
  mongodb_data:
    driver: local
  redis_data:
    driver: local
  file_uploads:
    driver: local

networks:
  microservices-network:
    driver: bridge
`;

  await fs.writeFile(
    path.join(dockerPath, 'docker-compose.dev.yml'),
    dockerComposeDevContent
  );
}

async generateDockerComposeProd() {
  const dockerPath = path.join(this.projectPath, 'docker');
  
  const dockerComposeProdContent = `version: '3.8'

services:
  # API Gateway
  api-gateway:
    build:
      context: ../api-gateway
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - API_GATEWAY_PORT=3000
      - JWT_ACCESS_SECRET=\${JWT_ACCESS_SECRET}
      - JWT_REFRESH_SECRET=\${JWT_REFRESH_SECRET}
      - JWT_SERVICE_SECRET=\${JWT_SERVICE_SECRET}
      - REDIS_URL=redis://redis:6379
    env_file:
      - .env.production
    depends_on:
      - redis
    networks:
      - microservices-network
    restart: unless-stopped
    deploy:
      replicas: 2
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure

  # Service Discovery
  service-discovery:
    build:
      context: ../service-discovery
      dockerfile: Dockerfile
    ports:
      - "8500:8500"
    environment:
      - NODE_ENV=production
      - SERVICE_DISCOVERY_PORT=8500
      - REDIS_URL=redis://redis:6379
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
    env_file:
      - .env.production
    depends_on:
      - redis
    networks:
      - microservices-network
    restart: unless-stopped
    deploy:
      replicas: 1

  # Auth Service
  auth-service:
    build:
      context: ../services/auth-service
      dockerfile: Dockerfile
    ports:
      - "3001:3001"
    environment:
      - NODE_ENV=production
      - PORT=3001
      - MONGODB_URI=mongodb://mongodb:27017/auth_service
      - REDIS_URL=redis://redis:6379
      - JWT_ACCESS_SECRET=\${JWT_ACCESS_SECRET}
      - JWT_REFRESH_SECRET=\${JWT_REFRESH_SECRET}
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
    env_file:
      - .env.production
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices-network
    restart: unless-stopped
    deploy:
      replicas: 2

  # User Service
  user-service:
    build:
      context: ../services/user-service
      dockerfile: Dockerfile
    ports:
      - "3002:3002"
    environment:
      - NODE_ENV=production
      - PORT=3002
      - MONGODB_URI=mongodb://mongodb:27017/user_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
    env_file:
      - .env.production
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices-network
    restart: unless-stopped
    deploy:
      replicas: 2

  # Notification Service
  notification-service:
    build:
      context: ../services/notification-service
      dockerfile: Dockerfile
    ports:
      - "3003:3003"
    environment:
      - NODE_ENV=production
      - PORT=3003
      - MONGODB_URI=mongodb://mongodb:27017/notification_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
    env_file:
      - .env.production
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices-network
    restart: unless-stopped
    deploy:
      replicas: 2

  # File Service
  file-service:
    build:
      context: ../services/file-service
      dockerfile: Dockerfile
    ports:
      - "3004:3004"
    environment:
      - NODE_ENV=production
      - PORT=3004
      - MONGODB_URI=mongodb://mongodb:27017/file_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
      - UPLOAD_PATH=/app/uploads
    env_file:
      - .env.production
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices-network
    volumes:
      - file_uploads:/app/uploads
    restart: unless-stopped
    deploy:
      replicas: 2

  # Payment Service
  payment-service:
    build:
      context: ../services/payment-service
      dockerfile: Dockerfile
    ports:
      - "3005:3005"
    environment:
      - NODE_ENV=production
      - PORT=3005
      - MONGODB_URI=mongodb://mongodb:27017/payment_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
      - STRIPE_SECRET_KEY=\${STRIPE_SECRET_KEY}
      - STRIPE_WEBHOOK_SECRET=\${STRIPE_WEBHOOK_SECRET}
    env_file:
      - .env.production
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices-network
    restart: unless-stopped
    deploy:
      replicas: 2

  # Analytics Service
  analytics-service:
    build:
      context: ../services/analytics-service
      dockerfile: Dockerfile
    ports:
      - "3006:3006"
    environment:
      - NODE_ENV=production
      - PORT=3006
      - MONGODB_URI=mongodb://mongodb:27017/analytics_service
      - REDIS_URL=redis://redis:6379
      - SERVICE_DISCOVERY_URL=http://service-discovery:8500
      - API_KEY=\${SERVICE_DISCOVERY_API_KEY}
    env_file:
      - .env.production
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices-network
    restart: unless-stopped
    deploy:
      replicas: 2

  # MongoDB Database
  mongodb:
    image: mongo:7.0
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_ROOT_USERNAME=\${MONGO_ROOT_USERNAME}
      - MONGO_INITDB_ROOT_PASSWORD=\${MONGO_ROOT_PASSWORD}
    volumes:
      - mongodb_data:/data/db
      - ./configs/mongo-init.js:/docker-entrypoint-initdb.d/mongo-init.js:ro
    networks:
      - microservices-network
    restart: unless-stopped
    deploy:
      replicas: 1

  # Redis Cache & Message Queue
  redis:
    image: redis:7.2-alpine
    ports:
      - "6379:6379"
    command: redis-server --requirepass \${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
      - ./configs/redis.conf:/usr/local/etc/redis/redis.conf
    networks:
      - microservices-network
    restart: unless-stopped
    deploy:
      replicas: 1

volumes:
  mongodb_data:
    driver: local
  redis_data:
    driver: local
  file_uploads:
    driver: local

networks:
  microservices-network:
    driver: bridge
`;

  await fs.writeFile(
    path.join(dockerPath, 'docker-compose.prod.yml'),
    dockerComposeProdContent
  );
}

async generateDockerEnv() {
  const dockerPath = path.join(this.projectPath, 'docker');
  
  // Main .env file
  const envContent = `# Docker Environment Variables
# Copy this file to .env and update with your actual values

# Application Settings
NODE_ENV=production

# JWT Secrets
JWT_ACCESS_SECRET=your-super-secure-jwt-access-secret-change-in-production
JWT_REFRESH_SECRET=your-super-secure-jwt-refresh-secret-change-in-production
JWT_SERVICE_SECRET=your-super-secure-jwt-service-secret-change-in-production

# Service Discovery
SERVICE_DISCOVERY_API_KEY=your-service-discovery-api-key-change-in-production

# Database
MONGO_ROOT_USERNAME=admin
MONGO_ROOT_PASSWORD=your-secure-mongo-password-change-in-production

# Redis
REDIS_PASSWORD=your-secure-redis-password-change-in-production

# Payment (Stripe)
STRIPE_SECRET_KEY=sk_test_your-stripe-secret-key
STRIPE_WEBHOOK_SECRET=whsec_your-stripe-webhook-secret

# Email (SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Mongo Express
MONGO_EXPRESS_USERNAME=admin
MONGO_EXPRESS_PASSWORD=password
`;

  await fs.writeFile(
    path.join(dockerPath, '.env.example'),
    envContent
  );

  // Development .env
  const devEnvContent = `# Development Environment Variables
NODE_ENV=development

# JWT Secrets (Development)
JWT_ACCESS_SECRET=dev_jwt_access_secret
JWT_REFRESH_SECRET=dev_jwt_refresh_secret
JWT_SERVICE_SECRET=dev_jwt_service_secret

# Service Discovery
SERVICE_DISCOVERY_API_KEY=dev_service_discovery_key

# Database
MONGO_ROOT_USERNAME=admin
MONGO_ROOT_PASSWORD=password

# Redis
REDIS_PASSWORD=password

# Payment (Stripe - Test Mode)
STRIPE_SECRET_KEY=sk_test_development_key
STRIPE_WEBHOOK_SECRET=whsec_development_secret

# Email (SMTP - Development)
SMTP_HOST=smtp.ethereal.email
SMTP_PORT=587
SMTP_USER=your-development-email@ethereal.email
SMTP_PASS=your-development-password

# Mongo Express
MONGO_EXPRESS_USERNAME=admin
MONGO_EXPRESS_PASSWORD=password
`;

  await fs.writeFile(
    path.join(dockerPath, '.env.development'),
    devEnvContent
  );
}

async generateDockerScripts() {
  const dockerPath = path.join(this.projectPath, 'docker');
  const scriptsPath = path.join(dockerPath, 'scripts');

  // Startup script
  const startupScript = `#!/bin/bash

# Microservices Docker Startup Script
set -e

echo "Starting Microservices Architecture..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Docker is not running. Please start Docker first."
    exit 1
fi

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "Warning: .env file not found. Using default values."
fi

# Create necessary directories
mkdir -p ./volumes/mongodb
mkdir -p ./volumes/redis
mkdir -p ./volumes/uploads
mkdir -p ./logs

echo "Building and starting services..."
docker-compose -f docker-compose.yml up -d --build

echo "Waiting for services to be healthy..."
sleep 30

# Check service health
echo "Checking service health..."
./scripts/health-check.sh

echo "Microservices architecture started successfully!"
echo ""
echo "Access points:"
echo "API Gateway: http://localhost:3000"
echo "Service Discovery: http://localhost:8500"
echo "Redis Commander: http://localhost:8081"
echo "Mongo Express: http://localhost:8082"
echo ""
echo "To view logs: docker-compose logs -f"
echo "To stop: docker-compose down"
`;

  await fs.writeFile(
    path.join(scriptsPath, 'start.sh'),
    startupScript
  );

  // Health check script
  const healthCheckScript = `#!/bin/bash

# Health Check Script for Microservices
set -e

echo "Checking microservices health..."

SERVICES=(
    "api-gateway:3000"
    "service-discovery:8500"
    "auth-service:3001"
    "user-service:3002"
    "notification-service:3003"
    "file-service:3004"
    "payment-service:3005"
    "analytics-service:3006"
    "mongodb:27017"
    "redis:6379"
)

ALL_HEALTHY=true

for service in "\${SERVICES[@]}"; do
    IFS=':' read -r name port <<< "\$service"
    
    if [ "\$name" = "mongodb" ]; then
        # Special check for MongoDB
        if docker-compose exec mongodb mongosh --eval "db.adminCommand('ping')" > /dev/null 2>&1; then
            echo "✓ $name is healthy"
        else
            echo "✗ $name is unhealthy"
            ALL_HEALTHY=false
        fi
    elif [ "\$name" = "redis" ]; then
        # Special check for Redis
        if docker-compose exec redis redis-cli ping | grep -q "PONG"; then
            echo "✓ $name is healthy"
        else
            echo "✗ $name is unhealthy"
            ALL_HEALTHY=false
        fi
    else
        # HTTP health check for other services
        if curl -f http://localhost:\$port/health > /dev/null 2>&1; then
            echo "✓ $name is healthy"
        else
            echo "✗ $name is unhealthy"
            ALL_HEALTHY=false
        fi
    fi
done

if [ "\$ALL_HEALTHY" = true ]; then
    echo ""
    echo "🎉 All services are healthy!"
    exit 0
else
    echo ""
    echo "❌ Some services are unhealthy. Check the logs with: docker-compose logs"
    exit 1
fi
`;

  await fs.writeFile(
    path.join(scriptsPath, 'health-check.sh'),
    healthCheckScript
  );

  // Make scripts executable
  await fs.chmod(path.join(scriptsPath, 'start.sh'), 0o755);
  await fs.chmod(path.join(scriptsPath, 'health-check.sh'), 0o755);
}
  async generateRootConfig() {
  // Generate root package.json
  await this.generateRootPackageJson();
  
  // Generate root README
  await this.generateRootReadme();
  
  // Generate environment files
  await this.generateRootEnv();
  
  // Generate additional root configuration files
  await this.generateRootScripts();
  await this.generateGitIgnore();
  await this.generateLicense();
}

async generateRootPackageJson() {
  const rootPackageJson = {
    name: this.config.projectName.toLowerCase().replace(/\s+/g, '-'),
    version: '1.0.0',
    description: this.config.description || 'Microservices-based Node.js backend application',
    private: true,
    workspaces: this.config.microservices.useWorkspaces ? [
      "api-gateway",
      "service-discovery", 
      "services/*",
      "shared"
    ] : undefined,
    scripts: {
      "dev": "npm run dev:services",
      "dev:services": "concurrently \"npm run dev:gateway\" \"npm run dev:discovery\" \"npm run dev:microservices\"",
      "dev:gateway": "cd api-gateway && npm run dev",
      "dev:discovery": "cd service-discovery && npm run dev",
      "dev:microservices": "concurrently \"cd services/auth-service && npm run dev\" \"cd services/user-service && npm run dev\" \"cd services/notification-service && npm run dev\" \"cd services/file-service && npm run dev\" \"cd services/payment-service && npm run dev\" \"cd services/analytics-service && npm run dev\"",
      "start": "docker-compose -f docker/docker-compose.yml up -d",
      "start:dev": "docker-compose -f docker/docker-compose.dev.yml up -d",
      "start:prod": "docker-compose -f docker/docker-compose.prod.yml up -d",
      "stop": "docker-compose -f docker/docker-compose.yml down",
      "stop:dev": "docker-compose -f docker/docker-compose.dev.yml down",
      "stop:prod": "docker-compose -f docker/docker-compose.prod.yml down",
      "build": "npm run build:services",
      "build:services": "concurrently \"cd api-gateway && npm run build\" \"cd service-discovery && npm run build\" \"cd services/auth-service && npm run build\" \"cd services/user-service && npm run build\" \"cd services/notification-service && npm run build\" \"cd services/file-service && npm run build\" \"cd services/payment-service && npm run build\" \"cd services/analytics-service && npm run build\"",
      "test": "npm run test:services",
      "test:services": "concurrently \"cd api-gateway && npm test\" \"cd service-discovery && npm test\" \"cd services/auth-service && npm test\" \"cd services/user-service && npm test\" \"cd services/notification-service && npm test\" \"cd services/file-service && npm test\" \"cd services/payment-service && npm test\" \"cd services/analytics-service && npm test\"",
      "clean": "npm run clean:modules && npm run clean:build",
      "clean:modules": "find . -name 'node_modules' -type d -prune -exec rm -rf '{}' +",
      "clean:build": "find . -name 'dist' -type d -prune -exec rm -rf '{}' +",
      "health-check": "cd docker && ./scripts/health-check.sh",
      "logs": "docker-compose -f docker/docker-compose.yml logs -f",
      "logs:dev": "docker-compose -f docker/docker-compose.dev.yml logs -f",
      "db:reset": "cd docker && ./scripts/reset-databases.sh",
      "lint": "eslint . --ext .js,.mjs --fix",
      "format": "prettier --write ."
    },
    devDependencies: {
      "concurrently": "^8.0.0",
      "nodemon": "^2.0.0",
      "eslint": "^8.0.0",
      "prettier": "^3.0.0",
      "jest": "^29.0.0",
      "supertest": "^6.0.0"
    },
    engines: {
      "node": ">=18.0.0",
      "npm": ">=9.0.0"
    },
    keywords: [
      "microservices",
      "nodejs",
      "express",
      "mongodb",
      "redis",
      "docker",
      "api-gateway",
      "service-discovery"
    ],
    author: this.config.author || "",
    license: "MIT"
  };

  await fs.writeJson(
    path.join(this.projectPath, 'package.json'),
    rootPackageJson,
    { spaces: 2 }
  );
}

async generateRootReadme() {
  const readmeContent = `# ${this.config.projectName}

${this.config.description || 'A microservices-based Node.js backend application'}

## 🏗️ Architecture

This project follows a microservices architecture with the following components:

### Core Services
- **API Gateway** - Single entry point for all client requests
- **Service Discovery** - Dynamic service registration and discovery
- **Shared Library** - Common utilities, middleware, and constants

### Business Services
- **Auth Service** - User authentication and authorization
- **User Service** - User management and profiles
- **Notification Service** - Email and push notifications
- **File Service** - File upload and management
- **Payment Service** - Payment processing with Stripe
- **Analytics Service** - Event tracking and analytics

### Infrastructure
- **MongoDB** - Primary database
- **Redis** - Caching and message queue
- **Docker** - Containerization and orchestration

## 🚀 Quick Start

### Prerequisites
- Node.js 18.0.0 or higher
- Docker and Docker Compose
- MongoDB (if running locally)
- Redis (if running locally)

### Development

1. **Clone and install dependencies:**
   \`\`\`bash
   git clone <repository-url>
   cd ${this.config.projectName.toLowerCase().replace(/\s+/g, '-')}
   npm install
   \`\`\`

2. **Start all services with Docker:**
   \`\`\`bash
   npm run start:dev
   \`\`\`

3. **Or start services individually:**
   \`\`\`bash
   npm run dev
   \`\`\`

### Production

1. **Build and start production services:**
   \`\`\`bash
   npm run build
   npm run start:prod
   \`\`\`

## 📁 Project Structure

\`\`\`
${this.config.projectName}/
├── api-gateway/                 # API Gateway service
├── service-discovery/           # Service Discovery service
├── services/                    # Business microservices
│   ├── auth-service/
│   ├── user-service/
│   ├── notification-service/
│   ├── file-service/
│   ├── payment-service/
│   └── analytics-service/
├── shared/                      # Shared utilities and middleware
├── docker/                      # Docker configuration
│   ├── docker-compose.yml
│   ├── docker-compose.dev.yml
│   ├── docker-compose.prod.yml
│   └── scripts/
├── kubernetes/                  # Kubernetes manifests (optional)
└── docs/                        # Documentation
\`\`\`

## 🔧 Configuration

### Environment Variables

Copy the example environment files and update with your values:

\`\`\`bash
cp docker/.env.example docker/.env
cp docker/.env.development docker/.env.dev
\`\`\`

Key environment variables:
- \`JWT_ACCESS_SECRET\` - JWT token secret
- \`MONGODB_URI\` - MongoDB connection string
- \`REDIS_URL\` - Redis connection string
- \`STRIPE_SECRET_KEY\` - Stripe API key

### Service Ports

| Service | Port | Description |
|---------|------|-------------|
| API Gateway | 3000 | Main entry point |
| Service Discovery | 8500 | Service registry |
| Auth Service | 3001 | Authentication |
| User Service | 3002 | User management |
| Notification Service | 3003 | Notifications |
| File Service | 3004 | File handling |
| Payment Service | 3005 | Payments |
| Analytics Service | 3006 | Analytics |

## 🛠️ Development

### Running Tests

\`\`\`bash
# Run all tests
npm test

# Run tests for specific service
cd services/auth-service && npm test
\`\`\`

### Code Quality

\`\`\`bash
# Lint code
npm run lint

# Format code
npm run format
\`\`\`

### Database Management

\`\`\`bash
# Reset databases
npm run db:reset

# Access MongoDB (via Docker)
docker exec -it ${this.config.projectName.toLowerCase().replace(/\s+/g, '-')}-mongodb-1 mongosh

# Access Redis (via Docker)
docker exec -it ${this.config.projectName.toLowerCase().replace(/\s+/g, '-')}-redis-1 redis-cli
\`\`\`

## 📊 Monitoring

### Health Checks

\`\`\`bash
# Check service health
npm run health-check

# View logs
npm run logs
\`\`\`

### Web Interfaces

- **Redis Commander**: http://localhost:8081
- **Mongo Express**: http://localhost:8082

## 🔐 API Documentation

### Authentication

Most endpoints require JWT authentication. Include the token in the Authorization header:

\`\`\`http
Authorization: Bearer <your-jwt-token>
\`\`\`

### Example API Calls

\`\`\`bash
# Register user
curl -X POST http://localhost:3000/api/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "securepassword"
  }'

# Login
curl -X POST http://localhost:3000/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "john@example.com",
    "password": "securepassword"
  }'
\`\`\`

## 🐳 Docker

### Development

\`\`\`bash
# Start development environment
docker-compose -f docker/docker-compose.dev.yml up -d

# View development logs
docker-compose -f docker/docker-compose.dev.yml logs -f
\`\`\`

### Production

\`\`\`bash
# Build and start production
docker-compose -f docker/docker-compose.prod.yml up -d --build

# Scale services
docker-compose -f docker/docker-compose.prod.yml up -d --scale auth-service=3 --scale user-service=2
\`\`\`

## 🚢 Deployment

### Docker Swarm

\`\`\`bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker/docker-compose.prod.yml ${this.config.projectName.toLowerCase().replace(/\s+/g, '-')}
\`\`\`

### Kubernetes

See \`kubernetes/\` directory for manifests.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

If you encounter any issues:

1. Check the service logs: \`npm run logs\`
2. Verify environment variables
3. Check Docker container status
4. Open an issue on GitHub

---

Built with ❤️ using Node.js and Microservices Architecture
`;

  await fs.writeFile(
    path.join(this.projectPath, 'README.md'),
    readmeContent
  );
}

async generateRootEnv() {
  // Generate root .env file
  const rootEnvContent = `# Root Environment Configuration
# This file contains global environment variables

NODE_ENV=development
PROJECT_NAME=${this.config.projectName}

# Logging
LOG_LEVEL=info
LOG_FORMAT=combined

# Security
BCRYPT_ROUNDS=12
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# API Configuration
API_VERSION=v1
API_PREFIX=/api

# CORS
CORS_ORIGIN=http://localhost:3000,http://localhost:5173
CORS_CREDENTIALS=true

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
`;

  await fs.writeFile(
    path.join(this.projectPath, '.env'),
    rootEnvContent
  );

  // Generate .env.example
  const envExampleContent = `# Environment Variables Example
# Copy this file to .env and update with your actual values

# Application
NODE_ENV=development
PROJECT_NAME=${this.config.projectName}

# Security
JWT_ACCESS_SECRET=your-super-secure-jwt-access-secret-change-in-production
JWT_REFRESH_SECRET=your-super-secure-jwt-refresh-secret-change-in-production
JWT_SERVICE_SECRET=your-super-secure-jwt-service-secret-change-in-production

# Database
MONGODB_URI=mongodb://localhost:27017
MONGO_ROOT_USERNAME=admin
MONGO_ROOT_PASSWORD=your-secure-password

# Redis
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=your-secure-password

# Service Discovery
SERVICE_DISCOVERY_API_KEY=your-service-discovery-api-key

# Payment (Stripe)
STRIPE_SECRET_KEY=sk_test_your-stripe-secret-key
STRIPE_WEBHOOK_SECRET=whsec_your-stripe-webhook-secret

# Email (SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# File Upload
MAX_FILE_SIZE=10485760
UPLOAD_PATH=./uploads

# Logging
LOG_LEVEL=info
LOG_SERVICES_HEALTH=false
`;

  await fs.writeFile(
    path.join(this.projectPath, '.env.example'),
    envExampleContent
  );
}

async generateRootScripts() {
  const scriptsPath = path.join(this.projectPath, 'scripts');
  await this.ensureDirectory(scriptsPath);

  // Setup script
  const setupScript = `#!/bin/bash

# Microservices Setup Script
echo "🚀 Setting up ${this.config.projectName}..."

# Check Node.js version
REQUIRED_NODE="18.0.0"
CURRENT_NODE=$(node -v | sed 's/v//')

if [ "$(printf '%s\\n' "$REQUIRED_NODE" "$CURRENT_NODE" | sort -V | head -n1)" != "$REQUIRED_NODE" ]; then
    echo "❌ Node.js version must be >= $REQUIRED_NODE. Current version: $CURRENT_NODE"
    exit 1
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Prerequisites check passed"

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p docker/volumes/mongodb
mkdir -p docker/volumes/redis
mkdir -p docker/volumes/uploads
mkdir -p docker/logs
mkdir -p services/auth-service/uploads
mkdir -p services/file-service/uploads

# Copy environment files
echo "⚙️  Setting up environment variables..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "📝 Created .env file from example"
else
    echo "📝 .env file already exists"
fi

if [ ! -f "docker/.env" ]; then
    cp docker/.env.example docker/.env
    echo "📝 Created docker/.env file from example"
else
    echo "📝 docker/.env file already exists"
fi

# Install dependencies
echo "📦 Installing dependencies..."

# Install root dependencies
npm install

# Install service dependencies
echo "📦 Installing service dependencies..."
cd api-gateway && npm install && cd ..
cd service-discovery && npm install && cd ..
cd services/auth-service && npm install && cd ../..
cd services/user-service && npm install && cd ../..
cd services/notification-service && npm install && cd ../..
cd services/file-service && npm install && cd ../..
cd services/payment-service && npm install && cd ../..
cd services/analytics-service && npm install && cd ../..

echo "✅ Setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Update .env and docker/.env files with your actual values"
echo "2. Run 'npm run start:dev' to start all services with Docker"
echo "3. Run 'npm run health-check' to verify all services are healthy"
echo ""
echo "Happy coding! 🎉"
`;

  await fs.writeFile(
    path.join(scriptsPath, 'setup.sh'),
    setupScript
  );

  // Database reset script
  const dbResetScript = `#!/bin/bash

# Database Reset Script
echo "🗑️  Resetting databases..."

# Stop services if running
docker-compose -f docker/docker-compose.yml down

# Remove volumes
docker volume rm ${this.config.projectName.toLowerCase().replace(/\s+/g, '-')}_mongodb_data
docker volume rm ${this.config.projectName.toLowerCase().replace(/\s+/g, '-')}_redis_data
docker volume rm ${this.config.projectName.toLowerCase().replace(/\s+/g, '-')}_file_uploads

# Recreate volumes
docker volume create ${this.config.projectName.toLowerCase().replace(/\s+/g, '-')}_mongodb_data
docker volume create ${this.config.projectName.toLowerCase().replace(/\s+/g, '-')}_redis_data
docker volume create ${this.config.projectName.toLowerCase().replace(/\s+/g, '-')}_file_uploads

echo "✅ Databases reset successfully"
echo "Start services again with: npm run start:dev"
`;
  const dockerPath = path.join(this.projectPath, 'docker');

  await fs.writeFile(
    path.join(dockerPath, 'scripts', 'reset-databases.sh'),
    dbResetScript
  );

  // Make scripts executable
  await fs.chmod(path.join(scriptsPath, 'setup.sh'), 0o755);
  await fs.chmod(path.join(dockerPath, 'scripts', 'reset-databases.sh'), 0o755);
}

async generateGitIgnore() {
  const gitignoreContent = `# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Production builds
dist/
build/

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Logs
logs
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*
lerna-debug.log*

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/
.nyc_output/

# Dependency directories
node_modules/
jspm_packages/

# Optional npm cache directory
.npm

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn Integrity file
.yarn-integrity

# dotenv environment variables file
.env

# parcel-bundler cache (https://parceljs.org/)
.cache
.parcel-cache

# next.js build output
.next

# nuxt.js build output
.nuxt

# vuepress build output
.vuepress/dist

# Serverless directories
.serverless

# FuseBox cache
.fusebox/

# DynamoDB Local files
.dynamodb/

# TernJS port file
.tern-port

# Stores VSCode versions used for testing VSCode extensions
.vscode-test

# Docker
docker/volumes/
docker/logs/

# Uploads
uploads/
services/*/uploads/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Temporary files
tmp/
temp/
`;

  await fs.writeFile(
    path.join(this.projectPath, '.gitignore'),
    gitignoreContent
  );
}

async generateLicense() {
  const licenseContent = `MIT License

Copyright (c) ${new Date().getFullYear()} ${this.config.author || this.config.projectName}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`;

  await fs.writeFile(
    path.join(this.projectPath, 'LICENSE'),
    licenseContent
  );
}


  getPackageJson() {
    const basePackage = super.getPackageJson();

    // Add microservices-specific dependencies
    if (this.config.microservices.messageQueue.includes('bullmq')) {
      basePackage.dependencies['bullmq'] = '^4.0.0';
      basePackage.dependencies['ioredis'] = '^5.3.0';
    }

    if (this.config.microservices.messageQueue.includes('rabbitmq')) {
      basePackage.dependencies['amqplib'] = '^0.10.0';
    }

    // Add API Gateway dependencies
    if (this.config.microservices.includeApiGateway) {
      basePackage.dependencies['http-proxy-middleware'] = '^2.0.0';
      basePackage.dependencies['express-http-proxy'] = '^2.0.0';
    }

    // Add service discovery dependencies
    if (this.config.microservices.includeServiceDiscovery) {
      basePackage.dependencies['consul'] = '^0.40.0';
    }

    return basePackage;
  }

  getEnvContent() {
    let env = super.getEnvContent();

    // Add microservices-specific environment variables
    env += `\n# Microservices Configuration\n`;
    env += `API_GATEWAY_PORT=3000\n`;
    env += `SERVICE_DISCOVERY_PORT=8500\n`;

    // Add service ports
    env += `\n# Service Ports\n`;
    this.config.microservices.services.forEach(service => {
      env += `${service.toUpperCase()}_SERVICE_PORT=${this.getServicePort(service)}\n`;
    });

    // Add Redis configuration for BullMQ
    if (this.config.microservices.messageQueue.includes('bullmq')) {
      env += `\n# Redis Configuration\n`;
      env += `REDIS_URL=redis://localhost:6379\n`;
      env += `REDIS_PASSWORD=\n`;
      env += `REDIS_DB=0\n`;
    }

    // Add RabbitMQ configuration
    if (this.config.microservices.messageQueue.includes('rabbitmq')) {
      env += `\n# RabbitMQ Configuration\n`;
      env += `RABBITMQ_URL=amqp://localhost:5672\n`;
      env += `RABBITMQ_USERNAME=guest\n`;
      env += `RABBITMQ_PASSWORD=guest\n`;
    }

    return env;
  }

  getServicePort(serviceName) {
    const portMap = {
      'auth': 3001,
      'user': 3002,
      'notification': 3003,
      'file': 3004,
      'payment': 3005,
      'analytics': 3006
    };
    return portMap[serviceName] || 3000;
  }
}