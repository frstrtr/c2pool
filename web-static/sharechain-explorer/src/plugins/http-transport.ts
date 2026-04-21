// shared.transport.http — plugin wrapper around createHttpTransport.
// Lets hosts obtain the baseline HTTP transport via the capability
// system instead of direct import. Alternative providers
// (e.g. qt.transport.webchannel) plug in under the same capability.
// Provides capability `transport.factory`.

import type { PluginDescriptor } from '../registry.js';
import { createHttpTransport, type HttpTransportOptions } from '../transport/http.js';
import type { Transport } from '../transport/types.js';

export type TransportFactory = (opts: HttpTransportOptions) => Transport;

export const HttpTransportPlugin: PluginDescriptor = {
  id: 'shared.transport.http',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'capability',
  provides: ['transport.factory.http'],
  priority: 0,
  capabilities: {
    'transport.factory.http': createHttpTransport satisfies TransportFactory,
  },
};
