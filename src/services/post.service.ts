import { ValidationError } from 'apollo-server-core';
import errorHandler from '../controllers/error.controller';
import deserializeUser from '../middleware/deserializeUser';
import PostModel, { PostFilter, PostInput } from '../schemas/post.schema';
import { Context } from '../types/context';

export default class PostService {
  async createPost(input: Partial<PostInput>, { req }: Context) {
    try {
      const user = await deserializeUser(req);
      const post = await PostModel.create({ ...input, user: user?._id });
      return {
        status: 'success',
        post,
      };
    } catch (error: any) {
      if (error.code === 11000)
        throw new ValidationError('Post with that title already exist');
      errorHandler(error);
    }
  }

  async getPost(id: string, { req }: Context) {
    try {
      await deserializeUser(req);
      const post = await PostModel.findById(id).populate('user');

      if (!post) return new ValidationError('No post with that id exists');

      return {
        status: 'success',
        post,
      };
    } catch (error: any) {
      errorHandler(error);
    }
  }

  async updatePost(id: string, input: Partial<PostInput>, { req }: Context) {
    try {
      const user = await deserializeUser(req);
      const post = await PostModel.findByIdAndUpdate(
        id,
        { ...input, user: user?._id },
        {
          new: true,
          runValidators: true,
        }
      );

      if (!post) return new ValidationError('No post with that id exists');
      return {
        status: 'success',
        post,
      };
    } catch (error: any) {
      errorHandler(error);
    }
  }

  async getPosts(input: PostFilter, { req }: Context) {
    try {
      const user = await deserializeUser(req);
      const postsQuery = PostModel.find({ user: user?._id }).populate('user');

      // Pagination
      const page = input.page || 1;
      const limit = input.limit || 10;
      const skip = (page - 1) * limit;

      const posts = await postsQuery
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit);
      return {
        status: 'success',
        results: posts.length,
        posts,
      };
    } catch (error: any) {
      errorHandler(error);
    }
  }

  async deletePost(id: string, { req }: Context) {
    try {
      await deserializeUser(req);
      const post = await PostModel.findByIdAndDelete(id);

      if (!post) return new ValidationError('No post with that id exists');

      return true;
    } catch (error: any) {
      errorHandler(error);
    }
  }
}
