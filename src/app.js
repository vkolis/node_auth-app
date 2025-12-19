import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { notFound } from './middlewares/notFound.js';
import { errorHandler } from './middlewares/errorHandler.js';
import {
  activateUser,
  findUserById,
  loginUser,
  registerUser,
  requestPasswordReset,
  resetPassword,
} from './services/userService.js';
import { auth } from './middlewares/auth.js';

dotenv.config();
export const app = express();

const activateSchema = z.object({
  token: z.string().min(1, 'Token is required'),
});

const registerSchema = z.object({
  name: z.string().trim().min(1, 'Name is required'),
  email: z.string().email('Valid email is required'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
});

const loginSchema = z.object({
  email: z.string().email('Valid email is required'),
  password: z.string().min(1, 'Password is required'),
});

const resetRequestSchema = z.object({
  email: z.string().email('Valid email is required'),
});

const resetConfirmSchema = z.object({
  token: z.string().min(1, 'Token is required'),
  newPassword: z.string().min(6, 'Password must be at least 6 characters'),
});

app.use(express.json());
app.use(cors({ origin: 'http://localhost:5173', credentials: true }));
app.use(cookieParser());

app.get('/health', (req, res) => {
  res.status(200).send('Server is running');
});

app.post('/auth/register', async (req, res, next) => {
  try {
    const { name, email, password } = registerSchema.parse(req.body);

    await registerUser({ name, email, password });

    res.status(201).json({
      message: 'Ми надіслали лист для активації. Перевірте пошту.',
    });
  } catch (error) {
    next(error);
  }
});

app.post('/auth/activate', async (req, res, next) => {
  try {
    const { token } = activateSchema.parse(req.body);
    const user = await activateUser(token);

    const authToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: '7d',
    });

    res.json({
      message: 'Акаунт активовано',
      user,
      token: authToken,
    });
  } catch (error) {
    next(error);
  }
});

app.post('/auth/login', async (req, res, next) => {
  try {
    const { email, password } = loginSchema.parse(req.body);
    const result = await loginUser({ email, password });

    if (result.needsActivation) {
      return res.json({
        message: 'Активуйте email перед входом',
        needsActivation: true,
        user: result.user,
      });
    }

    const authToken = jwt.sign(
      { userId: result.user.id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' },
    );

    res.json({
      message: 'Успішний вхід',
      user: result.user,
      token: authToken,
    });
  } catch (error) {
    next(error);
  }
});

app.get('/auth/me', auth, async (req, res, next) => {
  try {
    const user = await findUserById(req.user.userId);

    res.json({ user });
  } catch (error) {
    next(error);
  }
});

app.post('/auth/logout', auth, (req, res) => {
  res.status(200).json({ message: 'Успішний вихід' });
});

app.post('/auth/reset/request', async (req, res, next) => {
  try {
    const { email } = resetRequestSchema.parse(req.body);
    const resetToken = await requestPasswordReset(email);

    res.json({
      message: 'Якщо email існує, ми надіслали інструкцію для відновлення.',
      resetToken,
    });
  } catch (error) {
    next(error);
  }
});

app.post('/auth/reset/confirm', async (req, res, next) => {
  try {
    const { token, newPassword } = resetConfirmSchema.parse(req.body);

    await resetPassword(token, newPassword);

    res.json({ message: 'Пароль змінено' });
  } catch (error) {
    next(error);
  }
});

app.use(notFound);
app.use(errorHandler);
