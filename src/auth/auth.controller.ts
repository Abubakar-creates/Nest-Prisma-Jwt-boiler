import { Body, Controller, Get, Post, Request, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('auth')
export class AuthController {

    constructor(private authService: AuthService) { }


    @Post('register')
    async register(@Body() body: { email: string, password: string }) {
        const { email, password } = body;
        console.log('i got the values', email, password);
        return this.authService.register(email, password);
    }


    @Post('login')
    async login(@Body() body: { email: string, password: string }) {
        const { email, password } = body;
        return this.authService.login(email, password);
    }

    @UseGuards(JwtAuthGuard)
    @Get('profile')
    async profile(@Request() req) {
        return { message: 'You are authenticated' , user:req.user };
    }




}
