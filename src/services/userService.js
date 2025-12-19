import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import User from '../models/User.js';

const badRequest = (message) => {
  const error = new Error(message);

  error.status = 400;

  return error;
};

const publicUser = (user) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  active: user.active,
});

export const registerUser = async ({ name, email, password }) => {
  const normalizedEmail = email.toLowerCase();

  const existingUser = await User.findOne({
    where: { email: normalizedEmail },
  });

  if (existingUser) {
    throw badRequest('User already exists');
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const activationToken = uuidv4();

  const newUser = await User.create({
    name: name.trim(),
    email: normalizedEmail,
    passwordHash,
    activationToken,
    active: false,
  });

  return publicUser(newUser);
};

export const activateUser = async (token) => {
  const user = await User.findOne({ where: { activationToken: token } });

  if (!user) {
    throw badRequest('Invalid or expired activation token');
  }

  if (user.active) {
    throw badRequest('Account already activated');
  }

  user.active = true;
  user.activationToken = null;
  await user.save();

  return publicUser(user);
};

export const loginUser = async ({ email, password }) => {
  const normalizedEmail = email.toLowerCase();
  const user = await User.findOne({ where: { email: normalizedEmail } });

  if (!user) {
    throw badRequest('Invalid email or password');
  }

  const isValid = await bcrypt.compare(password, user.passwordHash);

  if (!isValid) {
    throw badRequest('Invalid email or password');
  }

  if (!user.active) {
    return {
      needsActivation: true,
      user: publicUser(user),
    };
  }

  return {
    user: publicUser(user),
  };
};

export const findUserById = async (id) => {
  const user = await User.findByPk(id);

  if (!user) {
    const error = new Error('User not found');

    error.status = 404;
    throw error;
  }

  return publicUser(user);
};
