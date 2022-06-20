import { PostResolver } from './post.resolver';
import UserResolver from './user.resolver';

export const resolvers = [UserResolver, PostResolver] as const;
