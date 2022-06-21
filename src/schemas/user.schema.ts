import {
  getModelForClass,
  prop,
  pre,
  ModelOptions,
  Severity,
  index,
} from '@typegoose/typegoose';
import { Field, InputType, ObjectType } from 'type-graphql';
import { IsEmail, MaxLength, MinLength } from 'class-validator';
import bcrypt from 'bcryptjs';
import config from 'config';

@pre<User>('save', async function (next) {
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(
    this.password,
    config.get<number>('costFactor')
  );
  this.passwordConfirm = undefined;
  return next();
})
@ModelOptions({
  schemaOptions: {
    timestamps: true,
  },
  options: {
    allowMixed: Severity.ALLOW,
  },
})
@index({ email: 1 })
export class User {
  @Field(() => String)
  readonly _id: string;

  @Field(() => String)
  @prop({ required: true })
  name: string;

  @Field(() => String)
  @prop({ required: true, unique: true, lowercase: true })
  email: string;

  @Field(() => String)
  @prop({ default: 'user' })
  role: string;

  @Field(() => String)
  @prop({ required: true, select: false })
  password: string;

  @Field(() => String)
  @prop({ required: true })
  passwordConfirm: string | undefined;

  @Field(() => String)
  @prop({ default: 'default.jpeg' })
  photo: string;

  @Field(() => Boolean)
  @prop({ default: true, select: false })
  verified: boolean;

  static async comparePasswords(
    hashedPassword: string,
    candidatePassword: string
  ) {
    return await bcrypt.compare(candidatePassword, hashedPassword);
  }
}

@InputType()
export class SignUpInput {
  @Field(() => String)
  @prop({ required: true })
  name: string;

  @IsEmail()
  @Field(() => String)
  email: string;

  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(32, { message: 'Password must be at most 32 characters long' })
  @Field(() => String)
  password: string;

  @Field(() => String)
  passwordConfirm: string | undefined;

  @Field(() => String)
  photo: string;
}

@InputType()
export class LoginInput {
  @IsEmail()
  @Field(() => String)
  email: string;

  @MinLength(8, { message: 'Invalid email or password' })
  @MaxLength(32, { message: 'Invalid email or password' })
  @Field(() => String)
  password: string;
}

@ObjectType()
export class UserData {
  @Field(() => String)
  readonly _id: string;

  @Field(() => String, { nullable: true })
  readonly id: string;

  @Field(() => String)
  name: string;

  @Field(() => String)
  email: string;

  @Field(() => String)
  role: string;

  @Field(() => String)
  photo: string;

  @Field(() => Date)
  createdAt: Date;

  @Field(() => Date)
  updatedAt: Date;
}

@ObjectType()
export class UserResponse {
  @Field(() => String)
  status: string;

  @Field(() => UserData)
  user: UserData;
}

@ObjectType()
export class LoginResponse {
  @Field(() => String)
  status: string;

  @Field(() => String)
  access_token: string;
}

const UserModel = getModelForClass<typeof User>(User);
export default UserModel;
