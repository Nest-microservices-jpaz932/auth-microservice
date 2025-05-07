import { Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Controller()
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @MessagePattern('auth.register.user')
    registerUser(@Payload() registerUserDto: RegisterDto) {
        return this.authService.registerUser(registerUserDto);
    }

    @MessagePattern('auth.login.user')
    loginUser(@Payload() loginUserDto: LoginDto) {
        return this.authService.loginUser(loginUserDto);
    }

    @MessagePattern('auth.verify.user')
    verifyUser(@Payload() token: string) {
        return this.authService.verifyToken(token);
    }
}
