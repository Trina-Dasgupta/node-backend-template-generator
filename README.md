# Node Backend Generator 🚀

[![npm version](https://img.shields.io/npm/v/node-backend-generator.svg)](https://www.npmjs.com/package/node-backend-generator)
[![npm downloads](https://img.shields.io/npm/dm/node-backend-generator.svg)](https://www.npmjs.com/package/node-backend-generator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org/)

A powerful CLI tool to generate professional, production-ready **Node.js backend templates** in seconds.  
Choose your database, features, and get a complete backend with industry best practices.

---

## ✨ Features

- 🚀 **Multiple Databases** – MongoDB (Mongoose), MySQL/PostgreSQL (Sequelize), Prisma, or Database-less  
- 🔐 **Authentication** – JWT with refresh tokens, bcrypt password hashing  
- 📁 **File Upload** – Multer with validation & multiple file support  
- 📧 **Email Service** – Nodemailer with ready templates (welcome, password reset, notifications)  
- 📚 **API Documentation** – Auto-generated Swagger/OpenAPI docs  
- 🐳 **Docker Support** – Dockerfile + docker-compose with database setup  
- 🛡️ **Security** – Helmet, CORS, rate limiting, input validation  
- ⚡ **Modern JS** – ES Modules & CommonJS support  
- 🎯 **Production Ready** – Error handling, logging, environment config  

---

## 🚀 Quick Start

### Using npx (Recommended — No Installation Needed)
```bash
npx node-backend-generator@latest
```

### Global Installation
```bash
npm install -g node-backend-generator

create-node-backend
```

### Local Installation
```bash
npm install node-backend-generator
npx create-node-backend
```

---

## 🧭 Usage

### 1️⃣ Run the Generator
```bash
npx node-backend-generator@latest
```

### 2️⃣ Follow the Interactive Prompts
You’ll be guided through setting up your project:

```bash
Enter your project name: my-awesome-api
```

**Example Interactive Setup:**
```
? Enter your project name: my-awesome-api
? Choose module system:
❯ ES Modules (MJS)
  CommonJS (CJS)

? Choose database ORM:
❯ Mongoose (MongoDB)
  Sequelize (MySQL/PostgreSQL)
  Prisma (Multi-database)
  None (API only)

? Select additional features:
◉ Authentication (JWT)
◉ API Documentation (Swagger)
◯ File Upload (Multer)
◯ Email Service (Nodemailer)
◯ Docker Support
◉ Rate Limiting
◉ Input Validation
```

---

### 3️⃣ Generated Project Structure
```
my-awesome-api/
├── server.js
├── package.json
├── .env
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── src/
│   ├── config/
│   ├── controllers/
│   ├── models/
│   ├── routes/
│   ├── middlewares/
│   ├── services/
│   └── utils/
├── uploads/
└── tests/
```

---

### 4️⃣ Get Started with Your New Project
```bash
cd my-awesome-api
npm install
cp .env.example .env

# Prisma only
npx prisma generate
npx prisma db push

# Start development server
npm run dev

# Or production
npm start
```

---

## 🎯 Available Scripts
```bash
npm start          # Start production server
npm run dev        # Start development server with nodemon
npm test           # Run tests
npm run lint       # Lint code
npm run lint:fix   # Auto-fix lint issues
```

---

## 📚 API Endpoints

### 🔐 Authentication (if enabled)
```
POST /api/auth/register      # Register user
POST /api/auth/login         # Login user
GET  /api/auth/profile       # Get logged-in profile
```

### 👤 User Routes
```
GET /api/users
GET /api/users/:id
```

### 📁 File Upload (if enabled)
```
POST /api/upload/single
POST /api/upload/multiple
```

### 📧 Email Service (if enabled)
```
POST /api/email/test
POST /api/email/password-reset
POST /api/email/welcome
```

### 🧰 Utilities
```
GET /health
GET /api-docs
```

---

## 🔧 Configuration

### Environment Variables (`.env`)
```env
# Server
NODE_ENV=development
PORT=3000

# Database
MONGODB_URI=mongodb://localhost:27017/your-db
# OR
DATABASE_URL="mysql://root:password@localhost:3306/your-db"

# JWT
JWT_SECRET=your_super_secret_key
JWT_EXPIRES_IN=7d

# Email
SMTP_HOST=your-smtp-host
SMTP_PORT=587
SMTP_USER=your-email@domain.com
SMTP_PASS=your-password
```

---

## 🗄️ Database Setup

### MongoDB (Mongoose)
1. Install MongoDB or use Atlas.  
2. Update `MONGODB_URI` in `.env`.  
3. Done! No schema migration needed.

### MySQL / PostgreSQL (Sequelize)
1. Install the respective DB.  
2. Create your database.  
3. Update `.env` credentials.  

### Prisma
```bash
npx prisma generate
npx prisma db push
```

---

## 🐳 Docker Support
If you selected Docker:
```bash
docker-compose up -d        # Start DB & app
docker build -t my-backend .
docker run -p 3000:3000 my-backend
```

---

## 🔐 Authentication Usage

### Register a User
```json
POST /api/auth/register
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "securepassword"
}
```

### Login
```json
POST /api/auth/login
{
  "email": "john@example.com",
  "password": "securepassword"
}
```

### Protected Routes
Include JWT token in headers:
```
Authorization: Bearer <your_jwt_token_here>
```

---

## 📁 File Upload Example
```js
const formData = new FormData();
formData.append('file', fileInput.files[0]);

fetch('/api/upload/single', {
  method: 'POST',
  headers: { Authorization: 'Bearer your-token' },
  body: formData,
});
```

---

## 📧 Email Service Example
### Send Test Email
```json
POST /api/email/test
{
  "email": "test@example.com"
}
```

### Request Password Reset
```json
POST /api/email/password-reset
{
  "email": "user@example.com"
}
```

---

## 🛠️ Customization

### Add a New Route
- Create a controller in `src/controllers/`
- Add a route in `src/routes/`
- Import it in `server.js`

### Add a New Model
- Add a model in `src/models/`
- Use it in your controller logic

### Add Middleware
- Create in `src/middlewares/`
- Register globally or per-route in `server.js`

---

## 🤝 Support

- 📘 **Docs:** Visit `/api-docs` after starting your server  
- 🐞 **Issues:** [GitHub Issues](https://github.com/)  
- 💬 **FAQ:** See in docs or discussions  

---

## 📄 License
MIT License — see [LICENSE](./LICENSE) for details.

---

## 🙏 Contributing
We welcome contributions!  
Please read our **Contributing Guide** before submitting PRs.

---

<div align="center">

✨ **Happy Coding!** ✨  
Generated with ❤️ by **Trina Dasgupta**

</div>
