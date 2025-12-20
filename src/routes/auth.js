import { Router } from 'express';
import { authController } from '../controllers/auth.controller';
import { auth } from '../middlewares/auth';

export const authRouter = new Router();

authRouter.post('/register', authController.register);
authRouter.post('/activate', authController.activate);
authRouter.post('/login', authController.login);
authRouter.post('/me', auth, authController.me);
authRouter.post('/logout', auth, authController.logout);
authRouter.post('/reset/request', authController.resetRequest);
authRouter.post('/reset/confirm', authController.resetConfirm);
authRouter.post('/password', auth, authController.userPassword);
authRouter.post('/profile', auth, authController.profile);
authRouter.post('/email', auth, authController.userEmail);
