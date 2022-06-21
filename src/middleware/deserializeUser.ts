import { AuthenticationError, ForbiddenError } from 'apollo-server-core';
import { Request } from 'express';
import errorHandler from '../controllers/error.controller';
import UserModel from '../models/user.model';
import redisClient from '../utils/connectRedis';
import { verifyJwt } from '../utils/jwt';

const deserializeUser = async (req: Request) => {
  try {
    // Get the access token
    let access_token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      access_token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies?.access_token) {
      const { access_token: token } = req.cookies;
      access_token = token;
    }

    if (!access_token) throw new AuthenticationError('No access token found');

    // Validate the Access token
    const decoded = verifyJwt<{ userId: string }>(
      access_token,
      'accessTokenPublicKey'
    );

    if (!decoded) throw new AuthenticationError('Invalid access token');

    // Check if the session is valid
    const session = await redisClient.get(decoded.userId);

    if (!session) throw new ForbiddenError('Session has expired');

    // Check if user exist
    const user = await UserModel.findById(JSON.parse(session)._id).select(
      '+verified'
    );

    if (!user || !user.verified) {
      throw new ForbiddenError(
        'The user belonging to this token no logger exist'
      );
    }

    return user;
  } catch (error: any) {
    errorHandler(error);
  }
};

export default deserializeUser;
