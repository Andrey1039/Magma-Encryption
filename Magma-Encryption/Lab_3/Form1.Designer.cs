﻿
namespace Lab_3
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.KeyTB = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.InputTB = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.Start = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.OutTB = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.OutTB1 = new System.Windows.Forms.TextBox();
            this.groupBox1.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBox1
            // 
            this.groupBox1.BackColor = System.Drawing.SystemColors.GradientInactiveCaption;
            this.groupBox1.Controls.Add(this.KeyTB);
            this.groupBox1.Controls.Add(this.label4);
            this.groupBox1.Controls.Add(this.InputTB);
            this.groupBox1.Controls.Add(this.label3);
            this.groupBox1.Controls.Add(this.Start);
            this.groupBox1.Controls.Add(this.label2);
            this.groupBox1.Controls.Add(this.OutTB);
            this.groupBox1.Controls.Add(this.label1);
            this.groupBox1.Controls.Add(this.OutTB1);
            this.groupBox1.Location = new System.Drawing.Point(12, 12);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(592, 427);
            this.groupBox1.TabIndex = 8;
            this.groupBox1.TabStop = false;
            // 
            // KeyTB
            // 
            this.KeyTB.Font = new System.Drawing.Font("Times New Roman", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.KeyTB.Location = new System.Drawing.Point(37, 138);
            this.KeyTB.MaxLength = 32;
            this.KeyTB.Name = "KeyTB";
            this.KeyTB.Size = new System.Drawing.Size(525, 34);
            this.KeyTB.TabIndex = 7;
            this.KeyTB.Text = "ffeeddccbbaa99887766554433221100";
            this.KeyTB.TextChanged += new System.EventHandler(this.KeyTB_TextChanged);
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Times New Roman", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.label4.Location = new System.Drawing.Point(37, 109);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(153, 26);
            this.label4.TabIndex = 8;
            this.label4.Text = "Введите ключ:";
            // 
            // InputTB
            // 
            this.InputTB.Font = new System.Drawing.Font("Times New Roman", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.InputTB.Location = new System.Drawing.Point(37, 66);
            this.InputTB.Name = "InputTB";
            this.InputTB.Size = new System.Drawing.Size(525, 34);
            this.InputTB.TabIndex = 1;
            this.InputTB.Text = "fedtba9876543210";
            this.InputTB.TextChanged += new System.EventHandler(this.InputTB_TextChanged);
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Times New Roman", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.label3.Location = new System.Drawing.Point(31, 340);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(304, 26);
            this.label3.TabIndex = 6;
            this.label3.Text = "Результат (расшифрованный):";
            // 
            // Start
            // 
            this.Start.Enabled = false;
            this.Start.Font = new System.Drawing.Font("Times New Roman", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.Start.Location = new System.Drawing.Point(206, 195);
            this.Start.Name = "Start";
            this.Start.Size = new System.Drawing.Size(165, 53);
            this.Start.TabIndex = 0;
            this.Start.Text = "Зашифровать";
            this.Start.UseVisualStyleBackColor = true;
            this.Start.Click += new System.EventHandler(this.Start_Click);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Times New Roman", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.label2.Location = new System.Drawing.Point(31, 265);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(291, 26);
            this.label2.TabIndex = 5;
            this.label2.Text = "Результат (зашифрованный):";
            // 
            // OutTB
            // 
            this.OutTB.Font = new System.Drawing.Font("Times New Roman", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.OutTB.Location = new System.Drawing.Point(37, 294);
            this.OutTB.Name = "OutTB";
            this.OutTB.ReadOnly = true;
            this.OutTB.Size = new System.Drawing.Size(525, 34);
            this.OutTB.TabIndex = 2;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Times New Roman", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.label1.Location = new System.Drawing.Point(37, 37);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(153, 26);
            this.label1.TabIndex = 4;
            this.label1.Text = "Введите текст:";
            // 
            // OutTB1
            // 
            this.OutTB1.Font = new System.Drawing.Font("Times New Roman", 13.8F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.OutTB1.Location = new System.Drawing.Point(37, 369);
            this.OutTB1.Name = "OutTB1";
            this.OutTB1.ReadOnly = true;
            this.OutTB1.Size = new System.Drawing.Size(525, 34);
            this.OutTB1.TabIndex = 3;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.SystemColors.GradientInactiveCaption;
            this.ClientSize = new System.Drawing.Size(621, 463);
            this.Controls.Add(this.groupBox1);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.Name = "Form1";
            this.Text = "Шифрование «Магма»";
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.TextBox InputTB;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Button Start;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox OutTB;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox OutTB1;
        private System.Windows.Forms.TextBox KeyTB;
        private System.Windows.Forms.Label label4;
    }
}

