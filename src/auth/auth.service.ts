import {
  BadRequestException,
  Injectable,
  NotFoundException,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import { AuthDto } from './dto/auth.dto';
import { verify } from 'argon2';
import { Response } from 'express';
import { CLIENT_DOMAIN } from 'src/main';

@Injectable()
export class AuthService {
  EXPIRE_DAY_REFRESH_TOKEN = 1;
  REFRESH_TOKEN_NAME = 'refreshToken';
  constructor(
    private jwt: JwtService,
    private userService: UserService,
  ) {}
  private generateToken(userId: string) {
    const data = { id: userId };
    const accessToken = this.jwt.sign(data, { expiresIn: '1h' });
    const refreshToken = this.jwt.sign(data, { expiresIn: '7d' });
    return { accessToken, refreshToken };
  }
  async generateNewTokens(refreshToken: string) {
    const result = await this.jwt.verifyAsync(refreshToken);
    if (!result) throw new UnauthorizedException('Invalid refresh token');
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...user } = await this.userService.getById(result.id);
    const tokens = this.generateToken(user.id);
    return { user, ...tokens };
  }
  addRefreshTokenToResponse(res: Response, refreshToken: string) {
    const expiresIn = new Date();
    expiresIn.setDate(expiresIn.getDate() + this.EXPIRE_DAY_REFRESH_TOKEN);
    res.cookie(this.REFRESH_TOKEN_NAME, refreshToken, {
      httpOnly: true,
      domain: CLIENT_DOMAIN,
      expires: expiresIn,
      secure: true, // secure if production
      sameSite: 'none', //lax if production
    });
  }
  removeRefreshTokenFromResponse(res: Response) {
    res.cookie(this.REFRESH_TOKEN_NAME, '', {
      httpOnly: true,
      domain: CLIENT_DOMAIN,
      expires: new Date(0),
      secure: true, // secure if production
      sameSite: 'none', //lax if production
    });
  }

  private async validateUser(dto: AuthDto) {
    const user = await this.userService.getByEmail(dto.email);
    if (!user) throw new NotFoundException('User not found');
    const isValid = await verify(user.password, dto.password);
    if (!isValid) throw new UnauthorizedException('Invalid password');
    return user;
  }
  async login(dto: AuthDto) {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...user } = await this.validateUser(dto);
    const tokens = this.generateToken(user.id);
    return { user, ...tokens };
  }
  async registration(dto: AuthDto) {
    const existedUser = await this.userService.getByEmail(dto.email);
    if (existedUser) throw new BadRequestException('user already exist!');
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...user } = await this.userService.create(dto);
    const tokens = this.generateToken(user.id);
    return { user, ...tokens };
  }
}
