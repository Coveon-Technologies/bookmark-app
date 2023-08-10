import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2'
import { error } from "console";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";

@Injectable()
export class AuthService {

  constructor(private prisma: PrismaService) { }

  async signup(dto: AuthDto) {
    try {
      // Generate the password hash
      const hash = await argon.hash(dto.password)

      // Save th new user in the db
      const user = await this.prisma.users.create({
        data: {
          email: dto.email,
          hash,
          link: "link"
        },
        select: {
          id: true,
          email: true,
          updatedAt: true,
          createdAt: true,
          firstName: true,
          lastName: true
        }
      });

      // Return the saved user
      return user;

    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException(
            'Credentials Taken'
          )
        }
      }
      throw error
    }
  }

  async signin(dto: AuthDto) {

    const user = await this.prisma.users.findUnique({
      where : {
        email: dto.email
      }
    })

    if(!user) throw new ForbiddenException('Credential incorrect')

    const pwMatch = await argon.verify(user.hash, dto.password)

    if(!pwMatch)  throw new ForbiddenException('Credential incorrect')

    // Send back the user info
    delete user.hash
    return user
  }
}