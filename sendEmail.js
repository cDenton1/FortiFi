const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "fortifiids@gmail.com",
    pass: "jvwh opts hnsr fcxs"
  }
});

function sendEmail(mailOptions) {
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
      } else {
        console.log("Email sent: " + info.response);
      }
    });
  }

const mailOptions = {
    to: "",
    subject: "Mobile Alert",
    text: ""
};

sendEmail(mailOptions);
