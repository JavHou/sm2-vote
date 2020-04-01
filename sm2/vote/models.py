from django.db import models

# Create your models here.


class Users(models.Model):
    username = models.CharField("用户名", max_length=255, unique=True)
    password = models.CharField("密码", max_length=255)
    ut= models.CharField("用户投的票",max_length=255,null=True)
    # skey = models.TextField("私钥")
    # pkey = models.TextField("公钥")
    # q = models.TextField("大素数")
    # n = models.TextField("素数")
    # g = models.TextField("基点")


class Votes(models.Model):
    votemes = models.TextField("盖章信息",unique=True)


class Tickets(models.Model):
    title = models.CharField("投票标题", max_length=255)
    description = models.CharField("选项描述", max_length=255)
    up = models.CharField("同意票数",max_length=255)
    down = models.CharField("反对票数",max_length=255)

