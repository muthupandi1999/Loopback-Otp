import { UserService } from '@loopback/authentication';
import { UserProfile, securityId } from '@loopback/security';
import { Credentials, UserRepository } from '../repositories/user.repository';
import { User } from '../models';
import { repository } from '@loopback/repository';
import { HttpErrors } from '@loopback/rest';
import { inject } from '@loopback/core';
import { BcryptHasher } from './hash.password.bcrypt';
import { PasswordHasherBindings } from '../keys';



export class MyUserService implements UserService<User, Credentials> {
  constructor(
    @repository(UserRepository)
    public userRepository: UserRepository,
    // @inject(PasswordHasherBindings.PASSWORD_HASHER)
    // public hasher: BcryptHasher,
  ) { }
  async verifyCredentials(credentials: Credentials): Promise<User> {
    const foundUser = await this.userRepository.findOne({
      where: {
        email: credentials.email,
      },
    });
    if (!foundUser) {
      throw new HttpErrors.NotFound(
        `user not found with this ${credentials.email}`,
      );
    }

    // const passwordMatched = await this.hasher.comparePassword(
    //   credentials.password,
    //   foundUser.password,
    // );
    // if (!passwordMatched) {
    //   throw new HttpErrors.Unauthorized('password is not valid');
    // }
    console.log(foundUser.isDelete)
    if (foundUser.isDelete) {
      throw new HttpErrors.NotAcceptable('Your account was deleted! Contact admin for re-enable your account!')
    }
    return foundUser;
  }
  convertToUserProfile(user: User): UserProfile {
    return { [securityId]: `${user.id}`, name: user.name, email: user.email }
  }
}
