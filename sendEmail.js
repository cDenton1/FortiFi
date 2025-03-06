const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "fortifiids@gmail.com",
    pass: "jvwh opts hnsr fcxs"
  }
});

const mailOptions = {
  from: "fortifiids@gmail.com",
  to: "denton.c19@gmail.com",
  subject: "Mobile Alert",
  text: "This is a test email alert!"
};

transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Email sent: " + info.response);
  }
});
