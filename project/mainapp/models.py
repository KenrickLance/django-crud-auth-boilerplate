from django.db import models
from django.core.validators import MaxValueValidator, MinValueValidator
from django.utils import timezone
from django.contrib.auth.models import User

import datetime



class ModelAllowDisplayInfo(models.Model):
    def display_info(self):
        info = {}
        for item in self._meta.fields:
            info[item.verbose_name] = self.__getattribute__(item.name)
        return info

    class Meta:
        abstract=True

class GenericModelMain(ModelAllowDisplayInfo):
    sex_choices = [
        ('',''),
        ('Male', 'Male'),
        ('Female', 'Female'),
    ]

    first_name = models.CharField('First name',max_length=254,)
    middle_name = models.CharField('Middle name', max_length=254)
    last_name = models.CharField('Last name', max_length=254)
    email = models.EmailField('Email address', max_length=254)
    sex = models.CharField('Sex', max_length=254, choices=sex_choices)
    birth_date = models.DateField('Date of birth')
    employment_date = models.DateField('Employment date', auto_now_add=True)
    termination_date = models.DateField('Termination date', default=timezone.now()+datetime.timedelta(days=365*3))

    def full_name(self):
        return self.first_name + ' ' + self.middle_name + ' ' + self.last_name


    def __str__(self):
        return f'{self.last_name}, {self.first_name} {self.middle_name}'

        



class GenericModelForeign(ModelAllowDisplayInfo):
    second_engineer = models.ForeignKey(GenericModelMain, default='', related_name='second_engineer', on_delete=models.SET_NULL, null=True, verbose_name='Second engineer')
    engine_cadet = models.ManyToManyField(GenericModelMain, default='', related_name='engine_cadet', verbose_name='Engine cadet')

