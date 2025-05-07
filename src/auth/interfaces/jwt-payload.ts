export interface JwtPayload {
    id: string;
    email: string;
    name: string;
}

export interface JwtResponse extends JwtPayload {
    iat: number;
    exp: number;
    sub: string;
}
