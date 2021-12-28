'use strict';

const EventEmitter = require('events');
const requestp = require('request-promise');

class KeystoneV3Authenticator extends EventEmitter {

    static getAppCredentialInstance(credentials) {
        return new KeystoneV3Authenticator(credentials, 'application_credential')
    }

    static getPasswordInstance(credentials) {
        return new KeystoneV3Authenticator(credentials, 'password')
    }

    constructor(credentials, type) {
        super();

        if (credentials === undefined || credentials === null || !Object.keys(credentials).length) {
            throw new Error('credentials are required');
        }

        if (!type) {
            throw new Error('type is required');
        }

        this.credentials = credentials;
        this.type = type;

        this.currentToken = null;
    }

    tryFindEndpointUrl(catalog, service, iface, regionId) {
        if (typeof iface === 'undefined') {
            iface = 'public';
        }

        const catalogEntry = catalog.find(x => x.name === service);
        if (!catalogEntry) {
            return null;
        }

        const endpoint = catalogEntry.endpoints.find(x => x.interface === iface && (regionId ? x.region_id == regionId : true));
        if (!endpoint) {
            return null;
        }

        return endpoint.url;
    }

    async getToken() {
        const credentials = this.credentials;
        const model = this.getAuthModel();

        const response = await requestp({
            method: 'POST',
            uri: credentials.endpointUrl + '/auth/tokens',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            json: model,
            resolveWithFullResponse: true
        });

        const catalog = response.body.token.catalog;
        const swiftUrl =
            this.tryFindEndpointUrl(catalog, 'swift', credentials.endpointUrlInterface, credentials.regionId)
            || this.tryFindEndpointUrl(catalog, 'radosgw-swift', credentials.endpointUrlInterface, credentials.regionId); // many OpenStack clouds use ceph radosgw to provide swift

        if (!swiftUrl) {
            throw new Error('could not find swift or radosgw-swift service in catalog');
        }

        return {
            token: response.headers['x-subject-token'],
            expires: new Date(response.body.token.expires_at), // expires_at is an ISO 8601 Date:
            swiftUrl: swiftUrl
        }
    };

    async authenticate() {
        if (!this.currentToken) {
            this.currentToken = await this.getToken();
        }

        const tokenPreRefreshInterval = 10000; // renew tokens 10s before they expire
        const requestedTokenExpiry = new Date(Date.now() + tokenPreRefreshInterval)
        if (requestedTokenExpiry > this.currentToken.expires) {
            this.currentToken = await this.getToken();
        }

        const validToken = this.currentToken;
        return {url: validToken.swiftUrl, token: validToken.token};
    }

    getAuthModel() {
        let model = {};

        if (this.type === 'application_credential') {
            model = {
                auth: {
                    identity: {
                        methods: [
                            'application_credential'
                        ],
                        application_credential: {
                            id: this.credentials.applicationId,
                            domain: {
                                id: this.credentials.domainId || 'default'
                            },
                            secret: this.credentials.applicationSecret,
                        }
                    }
                }
            }
        } else if (this.type === 'password') {
            model = {
                auth: {
                    identity: {
                        methods: [
                            'password'
                        ],
                        password: {
                            user: {
                                name: this.credentials.username,
                                password: this.credentials.password,
                                domain: {
                                    id: this.credentials.domainId
                                }
                            }
                        }
                    },
                    scope: {
                        project: {
                            id: this.credentials.projectId,
                            domain: {
                                id: this.credentials.domainId
                            }
                        }
                    }
                }
            };
        } else {
            throw new Error("Invalid auth method supplied");
        }

        return model
    }
}

module.exports = KeystoneV3Authenticator;
