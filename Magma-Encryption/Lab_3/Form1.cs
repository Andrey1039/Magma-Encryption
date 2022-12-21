using System;
using System.Text;
using System.Windows.Forms;

namespace Lab_3
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Start_Click(object sender, EventArgs e)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encryption test = new Encryption();

            string res = test.Encoding(InputTB.Text, KeyTB.Text);
            OutTB.Text =  res;
            OutTB1.Text = test.Decoding(res, KeyTB.Text); 
        }

        private void KeyTB_TextChanged(object sender, EventArgs e)
        {
            if (KeyTB.Text.Length == 32)
                Start.Enabled = true;
            else
                Start.Enabled = false;
        }

        private void InputTB_TextChanged(object sender, EventArgs e)
        {
            if (KeyTB.Text.Length == 32)
                Start.Enabled = true;
            else
                Start.Enabled = false;
        }
    }
    
}
