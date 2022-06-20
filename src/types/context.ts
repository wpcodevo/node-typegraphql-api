import { Request, Response } from 'express';
import { User } from '../schemas/user.schema';

export type Context = {
  req: Request;
  res: Response;
  deserializeUser: (req: Request) => Promise<User | undefined>;
};
