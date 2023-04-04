// Copyright IBM Corp. 2020. All Rights Reserved.
// Node module: loopback4-example-shopping
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {
    AuthorizationContext,
    AuthorizationDecision,
    AuthorizationMetadata,
  } from '@loopback/authorization';
  import {securityId, UserProfile} from '@loopback/security';
  import _ from 'lodash';
  
  // Instance level authorizer
  // Can be also registered as an authorizer, depends on users' need.
  export async function authorizeUser(
    authorizationCtx: AuthorizationContext,
    metadata: AuthorizationMetadata,
  ): Promise<AuthorizationDecision> {
    // No access if authorization details are missing
    let currentUser: UserProfile;

    if (authorizationCtx.principals.length > 0) {
      const user = _.pick(authorizationCtx.principals[0], [
        'id',
        'name',
        'role',
      ]);
      currentUser = {[securityId]: user.id, name: user.name, roles: user.role};

    } else {
      return AuthorizationDecision.DENY;
    }
    if (!currentUser.roles) {
      return AuthorizationDecision.DENY;
    }
  
    // Authorize everything that does not have a allowedRoles property
    if (!metadata.allowedRoles) {
      return AuthorizationDecision.ALLOW;
    }
  
    let roleIsAllowed = false;
    for (const role of currentUser.roles) {
      if (metadata.allowedRoles!.includes(role)) {
        roleIsAllowed = true;
        break;
      }
    }
    if (!roleIsAllowed) {
      return AuthorizationDecision.DENY;
    }
    // // Admin accounts bypass id verification
    // if (
    //   currentUser.roles.includes('admin') 
    // ) {
    //   return AuthorizationDecision.ALLOW;
    // }
  
    /**
     * Allow access only to owners, using token as source of truth
     *
     */
    if (currentUser[securityId] === authorizationCtx.principals[0].id) {
      return AuthorizationDecision.ALLOW;
    }
  
    return AuthorizationDecision.DENY;
  }