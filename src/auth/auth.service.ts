import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload, JwtResponse } from './interfaces/jwt-payload';
import { envs } from 'src/config/envs';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    private readonly logger = new Logger('AuthService');

    constructor(private readonly jwtService: JwtService) {
        super();
    }

    async onModuleInit() {
        await this.$connect();
        this.logger.log('Connected to the MongoDB');
    }

    signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }

    async registerUser(registerUserDto: RegisterDto) {
        const { email, name, password } = registerUserDto;
        try {
            const userExist = await this.user.findUnique({
                where: {
                    email,
                },
            });

            if (userExist) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists',
                });
            }

            const newUser = await this.user.create({
                data: {
                    email,
                    password: bcrypt.hashSync(password, 10),
                    name,
                },
            });

            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            const { password: __, ...userWithoutPassword } = newUser;

            return {
                user: userWithoutPassword,
                token: this.signJWT(userWithoutPassword),
            };
        } catch (error) {
            const errorMessage =
                error instanceof Error
                    ? error.message
                    : 'An unknown error occurred';
            throw new RpcException({
                status: 400,
                message: errorMessage,
            });
        }
    }

    async loginUser(loginUserDto: LoginDto) {
        const { email, password } = loginUserDto;
        try {
            const user = await this.user.findUnique({
                where: { email },
            });

            if (!user) {
                throw new RpcException({
                    status: 404,
                    message: 'Invalid credentials',
                });
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password);

            if (!isPasswordValid) {
                throw new RpcException({
                    status: 404,
                    message: 'Invalid credentials',
                });
            }

            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            const { password: __, ...userWithoutPassword } = user;

            return {
                user: userWithoutPassword,
                token: this.signJWT(userWithoutPassword),
            };
        } catch (error) {
            const errorMessage =
                error instanceof Error
                    ? error.message
                    : 'An unknown error occurred';
            throw new RpcException({
                status: 400,
                message: errorMessage,
            });
        }
    }

    verifyToken(token: string) {
        try {
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            const { sub, iat, exp, ...user } =
                this.jwtService.verify<JwtResponse>(token, {
                    secret: envs.jwt_secret,
                });

            return {
                user,
                token: this.signJWT(user),
            };
        } catch {
            throw new RpcException({
                status: 401,
                message: 'Invalid token',
            });
        }
    }
}
