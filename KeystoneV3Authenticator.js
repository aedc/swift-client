'use strict';

const EventEmitter = require('events');
const requestp = require('request-promise');

class KeystoneV3Authenticator extends EventEmitter {
    constructor(credentials) {
        super();

        this.credentials = credentials;
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
        const model = {
            auth: {
                identity: {
                    methods: [
                        'application_credential'
                    ],
                    application_credential: {
                        id: credentials.applicationId,
                        domain: {
                            id: credentials.domainId || 'default'
                        },
                        secret: credentials.applicationSecret,
                    }
                },
                scope: {
                    project: {
                        id: credentials.projectId,
                        domain: {
                            id: credentials.domainId
                        }
                    }
                }
            }
        };

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
}

module.exports = KeystoneV3Authenticator;
