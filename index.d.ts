declare class SwiftClient {
    constructor(authenticator: SwiftClient.SwiftAuthenticator);

    container(name: string): SwiftClient.SwiftContainer;
}

declare namespace SwiftClient {
    export class SwiftAuthenticator {
        constructor(url: string, username: string, password: string);
        authenticate();
    }

    export class KeystoneV3Authenticator {
        constructor(credentials: any, type: "application_credential" | "password");
        authenticate(): Promise<{ url: string, token: string }>
    }

    export class SwiftContainer {
        list(
            extra?: { [s: string]: string },
            // @see: https://developer.openstack.org/api-ref/object-store/?expanded=show-container-details-and-list-objects-detail#show-account-details-and-list-containers
            query?: string | { [s: string]: string }
        ): Promise<SwiftObject[]>;

        get(name: string, stream: WritableStream): Promise<void>;

        create(
            name: string,
            stream: ReadableStream,
            meta?: { [s: string]: string },
            extra?: { [s: string]: string }
        ): Promise<void>;

        meta(name: string): Promise<SwiftObjectMeta>;

        delete(name: string, when?: Date | number): Promise<void>;
    }

    interface SwiftObject {
        bytes: number; // 3344
        content_type: string; // "application/json"
        hash: string; // "28c3c00641adc0da09400d1d9a1aec91"
        name: string; // "0157f866cdd5cd92b14f261865000c92/Export-Xing.json"
        last_modified: string; // "2016-09-09T12:30:09.181050"
    }

    interface SwiftObjectMeta {
        author: string;
        year: string;
    }
}

export = SwiftClient;
