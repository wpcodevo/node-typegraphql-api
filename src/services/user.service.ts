import {
  AuthenticationError,
  ForbiddenError,
  ValidationError,
} from 'apollo-server-core';
import config from 'config';
import { CookieOptions } from 'express';
import errorHandler from '../controllers/error.controller';
import deserializeUser from '../middleware/deserializeUser';
import UserModel, { User } from '../models/user.model';
import { LoginInput } from '../schemas/user.schema';
import { Context } from '../types/context';
import redisClient from '../utils/connectRedis';
import { signJwt, verifyJwt } from '../utils/jwt';

// Cookie Options
const accessTokenExpiresIn = config.get<number>('accessTokenExpiresIn');
const refreshTokenExpiresIn = config.get<number>('refreshTokenExpiresIn');

const cookieOptions: CookieOptions = {
  httpOnly: true,
  domain: 'localhost',
  sameSite: 'none',
  secure: true,
};

if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

const accessTokenCookieOptions = {
  ...cookieOptions,
  maxAge: accessTokenExpiresIn * 60 * 1000,
  expires: new Date(Date.now() + accessTokenExpiresIn * 60 * 1000),
};

const refreshTokenCookieOptions = {
  ...cookieOptions,
  maxAge: refreshTokenExpiresIn * 60 * 1000,
  expires: new Date(Date.now() + refreshTokenExpiresIn * 60 * 1000),
};

async function findByEmail(email: string): Promise<User | null> {
  return UserModel.findOne({ email }).select('+password');
}

// Sign JWT Tokens
function signTokens(user: User) {
  const userId: string = user._id.toString();
  const access_token = signJwt({ userId }, 'accessTokenPrivateKey', {
    expiresIn: `${accessTokenExpiresIn}m`,
  });

  const refresh_token = signJwt({ userId }, 'refreshTokenPrivateKey', {
    expiresIn: `${refreshTokenExpiresIn}m`,
  });

  redisClient.set(userId, JSON.stringify(user), {
    EX: refreshTokenExpiresIn * 60,
  });

  return { access_token, refresh_token };
}

export default class UserService {
  // Register User
  async signUpUser(input: Partial<User>) {
    try {
      const user = await UserModel.create(input);
      return {
        status: 'success',
        user,
      };
    } catch (error: any) {
      if (error.code === 11000) {
        return new ValidationError('Email already exists');
      }
      errorHandler(error);
    }
  }

  // Login User
  async loginUser(input: LoginInput, { res }: Context) {
    try {
      const message = 'Invalid email or password';
      // 1. Find user by email
      const user = await findByEmail(input.email);

      if (!user) {
        return new AuthenticationError(message);
      }

      // 2. Compare passwords
      if (!(await UserModel.comparePasswords(user.password, input.password))) {
        return new AuthenticationError(message);
      }

      // 3. Sign JWT Tokens
      const { access_token, refresh_token } = signTokens(user);

      // 4. Add Tokens to Context
      res.cookie('access_token', access_token, accessTokenCookieOptions);
      res.cookie('refresh_token', refresh_token, refreshTokenCookieOptions);
      res.cookie('logged_in', 'true', {
        ...accessTokenCookieOptions,
        httpOnly: false,
      });

      return {
        status: 'success',
        access_token,
      };
    } catch (error: any) {
      errorHandler(error);
    }
  }

  // Get Currently Logged In User
  async getMe({ req, res, deserializeUser }: Context) {
    try {
      const user = await deserializeUser(req);
      return {
        status: 'success',
        user,
      };
    } catch (error: any) {
      errorHandler(error);
    }
  }

  // Refresh Access Token
  async refreshAccessToken({ req, res }: Context) {
    try {
      // Get the refresh token
      const { refresh_token } = req.cookies;

      // Validate the RefreshToken
      const decoded = verifyJwt<{ userId: string }>(
        refresh_token,
        'refreshTokenPublicKey'
      );

      if (!decoded) {
        throw new ForbiddenError('Could not refresh access token');
      }

      // Check if user's session is valid
      const session = await redisClient.get(decoded.userId);

      if (!session) {
        throw new ForbiddenError('User session has expired');
      }

      // Check if user exist and is verified
      const user = await UserModel.findById(JSON.parse(session)._id).select(
        '+verified'
      );

      if (!user || !user.verified) {
        throw new ForbiddenError('Could not refresh access token');
      }

      // Sign new access token
      const access_token = signJwt(
        { userId: user._id },
        'accessTokenPrivateKey',
        {
          expiresIn: `${accessTokenExpiresIn}m`,
        }
      );

      // Send access token cookie
      res.cookie('access_token', access_token, accessTokenCookieOptions);
      res.cookie('logged_in', 'true', {
        ...accessTokenCookieOptions,
        httpOnly: false,
      });

      return {
        status: 'success',
        access_token,
      };
    } catch (error) {
      errorHandler(error);
    }
  }

  // Logout User
  async logoutUser({ req, res }: Context) {
    try {
      const user = await deserializeUser(req);

      // Delete the user's session
      await redisClient.del(String(user?._id));

      // Logout user
      res.cookie('access_token', '', { maxAge: -1 });
      res.cookie('refresh_token', '', { maxAge: -1 });
      res.cookie('logged_in', '', { maxAge: -1 });

      return true;
    } catch (error) {
      errorHandler(error);
    }
  }
}
