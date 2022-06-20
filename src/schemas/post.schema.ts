import {
  getModelForClass,
  ModelOptions,
  prop,
  Ref,
  Severity,
} from '@typegoose/typegoose';
import { MinLength } from 'class-validator';
import { Field, InputType, ObjectType } from 'type-graphql';
import { User, UserData } from './user.schema';

@ModelOptions({
  schemaOptions: {
    timestamps: true,
  },
  options: {
    allowMixed: Severity.ALLOW,
  },
})
@ObjectType()
export class Post {
  @Field(() => String)
  readonly _id: string;

  @Field(() => String)
  @prop({ required: true, unique: true })
  title: string;

  @Field(() => String)
  @prop({ required: true })
  content: string;

  @Field(() => String)
  @prop({ required: true })
  category: string;

  @Field(() => String)
  @prop({ default: 'default.jpeg' })
  image: string;

  @Field(() => String)
  @prop({ required: true, ref: () => User })
  user: Ref<User>;
}

@InputType()
export class UpdatePostInput {
  @MinLength(10, { message: 'Title must be at least 10 characters long' })
  @Field(() => String, { nullable: true })
  title: string;

  @MinLength(10, { message: 'Content must be at least 10 characters long' })
  @Field(() => String, { nullable: true })
  content: string;

  @Field(() => String, { nullable: true })
  category: string;

  @Field(() => String, { nullable: true })
  image: string;
}

@InputType()
export class PostInput {
  @MinLength(10, { message: 'Title must be at least 10 characters long' })
  @Field(() => String)
  title: string;

  @MinLength(10, { message: 'Content must be at least 10 characters long' })
  @Field(() => String)
  content: string;

  @Field(() => String)
  category: string;

  @Field(() => String)
  image: string;
}

@InputType()
export class PostFilter {
  @Field(() => Number, { nullable: true, defaultValue: 1 })
  page: number;

  @Field(() => Number, { nullable: true, defaultValue: 10 })
  limit: number;
}

@ObjectType()
export class PostDataObj {
  @Field(() => String)
  readonly _id: string;

  @Field(() => String, { nullable: true })
  readonly id: string;

  @Field(() => String)
  title: string;

  @Field(() => String)
  category: string;

  @Field(() => String)
  content: string;

  @Field(() => String)
  image: string;

  @Field(() => Date)
  createdAt: Date;

  @Field(() => Date)
  updatedAt: Date;
}

@ObjectType()
export class PostPopulatedData extends PostDataObj {
  @Field(() => UserData)
  user: UserData;
}

@ObjectType()
export class PostData extends PostDataObj {
  @Field(() => String)
  user: string;
}

@ObjectType()
export class PostResponse {
  @Field(() => String)
  status: string;

  @Field(() => PostData)
  post: PostData;
}

@ObjectType()
export class PostPopulatedResponse {
  @Field(() => String)
  status: string;

  @Field(() => PostPopulatedData)
  post: PostPopulatedData;
}

@ObjectType()
export class PostListResponse {
  @Field(() => String)
  status: string;

  @Field(() => Number)
  results: number;

  @Field(() => [PostPopulatedData])
  posts: PostPopulatedData[];
}

const PostModel = getModelForClass<typeof Post>(Post);
export default PostModel;
