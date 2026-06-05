import logger from '#config/logger.js';
import { signupSchema } from '#validations/auth.validation.js';
import { formatValidationError } from '#validations/format.js';
import { createUser } from '#services/auth.service.js';
import { jwtoken } from '#utils/jwt.js';

export const signup = async (req, res, next) => {
  try {
    console.log('BODY:', req.body);
    const validationResult = signupSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: formatValidationError(validationResult.error),
      });
    }

    const { name, email, password, role } = validationResult.data;

    const user = await createUser({
      name,
      email,
      password,
      role,
    });

    const token = jwtoken.sign({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    logger.info(`User registered successfully: ${email}`);

    return res.status(201).json({
      message: 'User registered',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (e) {
    logger.error('Signup error', e);

    if (e.message === 'User with this email already exists') {
      return res.status(409).json({
        error: 'Email already exists',
      });
    }

    next(e);
  }
};
