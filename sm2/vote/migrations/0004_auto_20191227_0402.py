# Generated by Django 2.2.7 on 2019-12-27 04:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vote', '0003_auto_20191226_0758'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='users',
            name='g',
        ),
        migrations.RemoveField(
            model_name='users',
            name='n',
        ),
        migrations.RemoveField(
            model_name='users',
            name='pkey',
        ),
        migrations.RemoveField(
            model_name='users',
            name='q',
        ),
        migrations.RemoveField(
            model_name='users',
            name='skey',
        ),
        migrations.AddField(
            model_name='users',
            name='ut',
            field=models.CharField(max_length=255, null=True, verbose_name='用户投的票'),
        ),
    ]