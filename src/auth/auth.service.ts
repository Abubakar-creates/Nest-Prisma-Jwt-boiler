import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'prisma/prisma.service';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {

    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
    ) {}


    async register (email: string, password: string) {

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await this.prisma.user.create({
            data: {
                email,
                password : hashedPassword,
            },
        });
        return user;
    }


    async login (email: string, password: string) {
            
            const user = await this.prisma.user.findUnique({
                where: {
                    email,
                },
            });
    
            if (!user) {
                return null;
            }
    
            const passwordMatch = await bcrypt.compare(password, user.password);
    
            if (!passwordMatch) {
                return null;
            }

            const payload = {email : user.email, sub : user.id};
    
            const token = this.jwtService.sign(payload);
    
            return token;
        }

        async validateUser(payload:any) {
            return await this.prisma.user.findUnique({
                where: {
                    email: payload.email,
                },
            });
        }


}
