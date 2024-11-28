
# 📚 Book Notes App

**Book Notes App** is a responsive web application designed to help users organize and review their book notes efficiently. Built using modern web development technologies, the app emphasizes user-friendly design and seamless functionality. 

## ✨ Features

- **Secure Authentication**: Google OAuth integration using Passport.js for a hassle-free login experience.  
- **Responsive Design**: Tailwind CSS ensures the app looks great on all devices.  
- **Dynamic Note Management**: Create, update, and manage book notes effortlessly.  
- **Modern Tech Stack**: Built with Node.js, Express, and PostgreSQL for robust data management, and React for an interactive frontend.  

## 🚀 Tech Stack

- **Frontend**: React, Tailwind CSS  
- **Backend**: Node.js, Express  
- **Database**: PostgreSQL  
- **Authentication**: Google OAuth with Passport.js  

## 💡 Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/book-notes-app.git
   cd book-notes-app
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Set up your PostgreSQL database:
   - Create a database named `book_notes`.
   - Update your `.env` file with the following variables:
     ```
     DATABASE_URL=postgres://username:password@localhost:5432/book_notes
     GOOGLE_CLIENT_ID=your-client-id
     GOOGLE_CLIENT_SECRET=your-client-secret
     SESSION_SECRET=your-session-secret
     ```
4. Run database migrations (if applicable):
   ```bash
   npx sequelize-cli db:migrate
   ```
5. Start the development server:
   ```bash
   npm start
   ```

## 📖 About

This project was developed as part of my learning journey in full-stack web development. It showcases my ability to integrate modern tools and create practical, user-friendly solutions.

## 🔗 Demo

Check out the live version here: [Live Demo Link]  
View the project details: [Portfolio Link]  
