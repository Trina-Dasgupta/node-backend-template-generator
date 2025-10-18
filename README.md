# Node Backend Generator 🚀

[![npm version](https://img.shields.io/npm/v/node-backend-generator.svg)](https://www.npmjs.com/package/node-backend-generator)
[![npm downloads](https://img.shields.io/npm/dm/node-backend-generator.svg)](https://www.npmjs.com/package/node-backend-generator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org/)

A powerful CLI tool to generate professional, production-ready **Node.js backend templates** in seconds.  
Choose your database, architecture, and features — and get a complete backend with best practices baked in.

---

## ⚡ Quick Overview

**Node Backend Generator** helps you **generate production-ready Node.js backends** in seconds.  
Choose between **Monolithic or Microservices architecture**, with built-in features like authentication, Docker setup, Swagger docs, file uploads, and more.

---

## ✨ Key Features

- 🏗️ **Architecture Choice** – Monolithic or Microservices  
- 🗄️ **Multiple Databases** – MongoDB, PostgreSQL, MySQL, or DB-less  
- 🔐 **Built-in Auth** – JWT, bcrypt, refresh tokens  
- 🐳 **Docker Ready** – Full containerization support  
- 📚 **Auto Documentation** – Swagger/OpenAPI  
- 🛡️ **Security** – Helmet, CORS, rate limiting  
- 📧 **Email Service** – Nodemailer with templates  
- 📁 **File Upload** – Multer with validation  
- ⚡ **Modern JavaScript** – ES Modules & CommonJS support  
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

## 🎯 Interactive Setup

The CLI guides you through:

```
? Project name: my-api
? Architecture:
❯ Monolithic
  Microservices

? Database:
❯ MongoDB (Mongoose)
  PostgreSQL (Prisma)
  MySQL (Sequelize)
  None

? Features:
◉ Authentication | ◉ Docker | ◉ API Docs
◉ File Upload   | ◉ Email  | ◉ Rate Limiting
```

---

## 📁 Generated Project Structure

```
my-api/
├── src/
│   ├── controllers/   # Business logic
│   ├── models/        # Database models
│   ├── routes/        # API endpoints
│   ├── middlewares/   # Auth, validation
│   └── config/        # DB, environment
├── docker-compose.yml # Full stack setup
├── package.json       # Scripts & dependencies
└── .env               # Environment config
```

---

## 🔧 Get Started

```bash
cd my-api
npm install
cp .env.example .env
npm run dev
```

Visit: [http://localhost:3000/api-docs](http://localhost:3000/api-docs) for API documentation.

---

## 🐳 Docker Setup

```bash
# Start everything
docker-compose up -d

# Scale microservices
docker-compose up -d --scale auth-service=2 --scale user-service=2
```

---

## 📚 API Examples

### 🔐 Authentication
```bash
# Register
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"John","email":"john@test.com","password":"secret"}'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@test.com","password":"secret"}'
```

### 📁 File Upload
```js
const formData = new FormData();
formData.append('file', file);

fetch('/api/upload/single', {
  method: 'POST',
  headers: { 'Authorization': 'Bearer token' },
  body: formData
});
```

---

## 🛠️ Customization

- **Add Routes:** Create under `src/routes/` + logic in `src/controllers/`
- **Add Models:** Define in `src/models/`
- **Add Middleware:** Add to `src/middlewares/` and import globally or per-route

---

## 🤝 Support

- 📘 **Docs:** [http://localhost:3000/api-docs](http://localhost:3000/api-docs)
- 🐞 **Issues:** GitHub Issues
- 📄 **License:** MIT License

---

<div align="center">

### Start building your next great API in seconds! 🎉  
Generated with ❤️ by **Node Backend Generator**

</div>

---

## 🧩 Full Feature Reference (Detailed Section)

> For users who want the complete setup details, here’s the expanded guide below ⬇️

---

### 🧭 Usage
```bash
npx node-backend-generator@latest
```

Follow the setup prompts, select your preferences, and your backend will be ready instantly.

---

### 🏗️ Example Structure (Detailed)
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

### 🧰 Available Scripts
```bash
npm start          # Start production server
npm run dev        # Development with nodemon
npm test           # Run tests
npm run lint       # Lint code
npm run lint:fix   # Auto-fix lint issues
```

---

### 🔐 Authentication Usage
```json
POST /api/auth/register
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "securepassword"
}
```
```json
POST /api/auth/login
{
  "email": "john@example.com",
  "password": "securepassword"
}
```

Add JWT token:
```
Authorization: Bearer <your_jwt_token_here>
```

---

### 🧾 Environment Variables
```env
# Server
NODE_ENV=development
PORT=3000

# Database
MONGODB_URI=mongodb://localhost:27017/your-db
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

### 🧱 Database Setup

**MongoDB (Mongoose)**
- Update `MONGODB_URI` in `.env`
- Done.

**MySQL / PostgreSQL (Sequelize)**
- Update `.env` credentials.

**Prisma**
```bash
npx prisma generate
npx prisma db push
```

---

### 🐳 Docker Support (Detailed)
```bash
docker-compose up -d
docker build -t my-backend .
docker run -p 3000:3000 my-backend
```

---

### 📧 Email Example
```json
POST /api/email/test
{
  "email": "test@example.com"
}
```

---

### 🛠️ Extend Functionality
- **Controllers:** Add in `src/controllers`
- **Routes:** Add in `src/routes`
- **Middlewares:** Add in `src/middlewares`

---

## 📄 License
MIT License — see [LICENSE](./LICENSE)

---

<div align="center">

✨ **Happy Coding!** ✨  
Built with ❤️ by **Trina Dasgupta**

</div>
