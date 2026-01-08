/**
 * Relay Service Client
 *
 * WebSocket client for communicating with the MPC wallet relay service.
 */

import WebSocket from 'ws';

export interface ApprovalRequestEvent {
  sessionId: string;
  userId: string;
  agentName?: string;
  to: string;
  value: string;
  chain: string;
  chainId: number;
  data?: string;
  gasEstimate?: string;
  timestamp: number;
}

export interface ApprovalResponse {
  approved: boolean;
  userId: string;
  timestamp: number;
  reason?: string;
}

type ApprovalHandler = (event: ApprovalRequestEvent) => Promise<void>;

export class RelayClient {
  private url: string;
  private ws: WebSocket | null = null;
  private approvalHandlers: ApprovalHandler[] = [];
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectDelay = 1000;

  constructor(url: string) {
    this.url = url;
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.url);

        this.ws.on('open', () => {
          console.log('[Relay] Connected');
          this.reconnectAttempts = 0;
          resolve();
        });

        this.ws.on('message', (data) => {
          this.handleMessage(data.toString());
        });

        this.ws.on('close', () => {
          console.log('[Relay] Connection closed');
          this.attemptReconnect();
        });

        this.ws.on('error', (error) => {
          console.error('[Relay] Error:', error);
          if (this.reconnectAttempts === 0) {
            reject(error);
          }
        });
      } catch (error) {
        reject(error);
      }
    });
  }

  async disconnect(): Promise<void> {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  private async attemptReconnect(): Promise<void> {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('[Relay] Max reconnection attempts reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    console.log(`[Relay] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);

    await new Promise((resolve) => setTimeout(resolve, delay));

    try {
      await this.connect();
    } catch (error) {
      console.error('[Relay] Reconnection failed:', error);
    }
  }

  private handleMessage(data: string): void {
    try {
      const message = JSON.parse(data);

      switch (message.type) {
        case 'approval_request':
          this.handleApprovalRequest(message.payload);
          break;

        case 'session_update':
          console.log('[Relay] Session update:', message.payload);
          break;

        case 'ping':
          this.send({ type: 'pong' });
          break;

        default:
          console.log('[Relay] Unknown message type:', message.type);
      }
    } catch (error) {
      console.error('[Relay] Failed to parse message:', error);
    }
  }

  private async handleApprovalRequest(payload: ApprovalRequestEvent): Promise<void> {
    for (const handler of this.approvalHandlers) {
      try {
        await handler(payload);
      } catch (error) {
        console.error('[Relay] Approval handler error:', error);
      }
    }
  }

  onApprovalRequest(handler: ApprovalHandler): void {
    this.approvalHandlers.push(handler);
  }

  async submitApproval(sessionId: string, response: ApprovalResponse): Promise<void> {
    this.send({
      type: 'approval_response',
      payload: {
        sessionId,
        ...response,
      },
    });
  }

  async subscribe(userId: string): Promise<void> {
    this.send({
      type: 'subscribe',
      payload: { userId },
    });
  }

  private send(message: object): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.warn('[Relay] Cannot send - not connected');
    }
  }
}
