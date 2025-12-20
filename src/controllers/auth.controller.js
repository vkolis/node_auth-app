import jwt from 'jsonwebtoken';
import {
  sendActivationEmail,
  sendEmailChangeNotice,
  sendResetEmail,
} from '../services/emailService';
import {
  activateUser,
  changePassword,
  findUserById,
  loginUser,
  registerUser,
  requestPasswordReset,
  resetPassword,
  updateEmail,
  updateProfile,
} from '../services/userService';
import {
  activateSchema,
  changeEmailSchema,
  changePasswordSchema,
  changeProfileSchema,
  loginSchema,
  registerSchema,
  resetConfirmSchema,
  resetRequestSchema,
} from '../zod/zodSchemas';

const register = async (req, res, next) => {
  try {
    const { name, email, password } = registerSchema.parse(req.body);

    const { activationToken } = await registerUser({ name, email, password });

    await sendActivationEmail({ to: email, token: activationToken });

    res.status(201).json({
      message: 'Ми надіслали лист для активації. Перевірте пошту.',
    });
  } catch (error) {
    next(error);
  }
};

const activate = async (req, res, next) => {
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
};

const login = async (req, res, next) => {
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
};

const me = async (req, res, next) => {
  try {
    const user = await findUserById(req.user.userId);

    res.json({ user });
  } catch (error) {
    next(error);
  }
};

const logout = (req, res) => {
  res.status(200).json({ message: 'Успішний вихід' });
};

const resetRequest = async (req, res, next) => {
  try {
    const { email } = resetRequestSchema.parse(req.body);
    const result = await requestPasswordReset(email);

    if (result?.resetToken) {
      await sendResetEmail({ to: email, token: result.resetToken });
    }

    res.json({
      message: 'Якщо email існує, ми надіслали інструкцію для відновлення.',
    });
  } catch (error) {
    next(error);
  }
};

const resetConfirm = async (req, res, next) => {
  try {
    const { token, newPassword } = resetConfirmSchema.parse(req.body);

    await resetPassword(token, newPassword);

    res.json({ message: 'Пароль змінено' });
  } catch (error) {
    next(error);
  }
};

const userPassword = async (req, res, next) => {
  try {
    const { oldPassword, newPassword } = changePasswordSchema.parse(req.body);

    await changePassword({ userId: req.user.userId, oldPassword, newPassword });
    res.json({ message: 'Пароль змінено' });
  } catch (error) {
    next(error);
  }
};

const profile = async (req, res, next) => {
  try {
    const { name } = changeProfileSchema.parse(req.body);

    const user = await updateProfile({ userId: req.user.userId, name });

    res.json({ message: 'Профіль оновлено', user });
  } catch (error) {
    next(error);
  }
};

const userEmail = async (req, res, next) => {
  try {
    const { password, newEmail } = changeEmailSchema.parse(req.body);

    const oldEmail = (await findUserById(req.user.userId)).email;

    await sendEmailChangeNotice({ to: oldEmail, newEmail });

    const user = await updateEmail({
      userId: req.user.userId,
      password,
      email: newEmail,
    });

    res.json({ message: 'Email змінено. Ми повідомили стару адресу.', user });
  } catch (error) {
    next(error);
  }
};

export const authController = {
  register,
  activate,
  login,
  me,
  logout,
  resetRequest,
  resetConfirm,
  userPassword,
  profile,
  userEmail,
};
