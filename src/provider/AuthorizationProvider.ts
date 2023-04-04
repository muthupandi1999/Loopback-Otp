import { AuthorizationContext, AuthorizationDecision, AuthorizationMetadata, Authorizer } from '@loopback/authorization';
import { Provider } from '@loopback/core';

export class MyAuthorizationProvider implements Provider<Authorizer> {
  constructor() {
  }

  value(): Authorizer {
    return this.authorize.bind(this);
  }

  async authorize(
    context: AuthorizationContext,
    metadata: AuthorizationMetadata,
  ) {    
    if (
      context.resource === 'OrderController.prototype.cancelOrder' &&
      context.principals[0].name === 'user-01'
    ) {
      return AuthorizationDecision.ALLOW;
    }
    return AuthorizationDecision.ALLOW;
  }
}