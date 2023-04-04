import { BindingScope, injectable } from '@loopback/core';
import nodemailer from 'nodemailer';

@injectable({ scope: BindingScope.TRANSIENT })
export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      // port: 2525, // your SMTP port
      // secure: false, // false for TLS; true for SSL
      auth: {
        user: "mahespandi0321@gmail.com",
        pass: 'qfvqbsmvlgyxhvnv',
      },
    });
    // this.transporter = nodemailer.createTransport(MAIL_SETTINGS);
  }

  async sendEmail(to: string, subject: string, text: string) {
    const mailOptions = {
      from: 'mahespandi0321@gmail.com	',
      to,
      subject,
      html: text,
    };

    return this.transporter.sendMail(mailOptions);
  }
}