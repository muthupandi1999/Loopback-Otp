import { AuthenticationComponent, registerAuthenticationStrategy } from '@loopback/authentication';
import { AuthorizationComponent } from '@loopback/authorization';
import { BootMixin } from '@loopback/boot';
import { ApplicationConfig } from '@loopback/core';
import { RepositoryMixin } from '@loopback/repository';
import { RestApplication } from '@loopback/rest';
import { RestExplorerBindings, RestExplorerComponent } from '@loopback/rest-explorer';
import { ServiceMixin } from '@loopback/service-proxy';
import path from 'path';

import { JWTStrategy } from './authentication-stategies/jwt-strategy';
import { PasswordHasherBindings, TokenServiceBindings, TokenServiceConstants, UserServiceBindings } from './keys';
import { MySequence } from './sequence';
import { EmailService } from './services/email.service';
// import { SmsService } from './services/sms.service';
import { SmsService } from './services/phoneOtp.service';
import { SMSBindings } from './keys';

import { BcryptHasher } from './services/hash.password.bcrypt';
import { JWTService } from './services/jwt-service';
import { MyUserService } from './services/user.service';

export { ApplicationConfig };

export class LoopbacktestApplication extends BootMixin(
  ServiceMixin(RepositoryMixin(RestApplication)),
) {
  constructor(options: ApplicationConfig = {}) {
    super(options);

    // set up bindings
    this.setupBinding();

    registerAuthenticationStrategy(this, JWTStrategy);
    this.component(AuthorizationComponent);
    this.component(AuthenticationComponent);
    // Set up the custom sequence
    this.sequence(MySequence);

    // Set up default home page
    this.static('/', path.join(__dirname, '../public'));

    // Customize @loopback/rest-explorer configuration here
    this.configure(RestExplorerBindings.COMPONENT).to({
      path: '/explorer',
    });
    this.component(RestExplorerComponent);
    this.api({
      openapi: '3.0.2',
      info: { title: 'test', version: '1' },
      paths: {},
      components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer'
          }
        },
        servers: [{ url: '/' }],
      }
    })

    this.projectRoot = __dirname;
    // Customize @loopback/boot Booter Conventions here
    this.bootOptions = {
      controllers: {
        // Customize ControllerBooter Conventions here
        dirs: ['controllers'],
        extensions: ['.controller.js'],
        nested: true,
      },
    };
  }
  setupBinding(): void {
    // this.bind(PasswordHasherBindings.PASSWORD_HASHER).toClass(BcryptHasher);
    // this.bind(PasswordHasherBindings.ROUNDS).to(10);
    this.bind(UserServiceBindings.USER_SERVICE).toClass(MyUserService);
    this.bind('services.EmailService').toClass(EmailService);
    this.bind(SMSBindings.SmsService).toClass(SmsService);
    this.bind('sms.apiKey').to('f7eeff65');
    this.bind('sms.apiSecret').to('6jwAPLbssEDD4NHv');
    this.bind('sms.from').to('8489215350');
    this.bind(TokenServiceBindings.TOKEN_SERVICE).toClass(JWTService);
    this.bind(TokenServiceBindings.TOKEN_SECRET).to(
      TokenServiceConstants.TOKEN_SECRET_VALUE,
    );
    this.bind(TokenServiceBindings.TOKEN_EXPIRES_IN).to(
      TokenServiceConstants.TOKEN_EXPIRES_IN_VALUE,
    );

  }
}
