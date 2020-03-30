import { Pipe, PipeTransform } from '@angular/core';

@Pipe({name: 'timeAgo'})
export class TimeAgoPipe implements PipeTransform {
  transform(value: Date): any {
    // const targetDate = Date.parse(value);
    const now = Date.now();
    const valuems = Date.parse(value.toString());
    const delta = now - valuems;

    const deltaInDays = this.getDays(delta);
    const deltaInMonths = Math.floor(this.getDays(delta) / 30);
    const deltaInHours = Math.floor(this.getHours(delta));
    const deltaInMinutes = Math.floor(this.getMinutes(delta));
    const deltaInSeconds = Math.floor(this.getSeconds(delta));


    if (deltaInDays > 546) {
        return Math.floor(deltaInDays / 365) + ' years ago';
    }
    if (deltaInDays >= 345 && deltaInDays <= 545) {
        return 'a year ago';
    }
    if (deltaInDays > 45 && deltaInDays < 345) {
        return deltaInMonths + ' months ago';
    }
    if (deltaInDays > 25 && deltaInDays <= 45) {
        return 'a month ago';
    }
    if (deltaInHours > 36 && deltaInDays <= 25) {
        return Math.floor(deltaInDays) + ' days ago';
    }
    if (deltaInHours > 22 && deltaInHours <= 36) {
        return 'a day ago';
    }
    if (deltaInMinutes > 90 && deltaInHours <= 22) {
        return deltaInHours + ' hours ago';
    }
    if (deltaInMinutes > 45 && deltaInMinutes <= 90) {
        return 'an hour ago';
    }
    if (deltaInSeconds > 90 && deltaInMinutes <= 45) {
        return deltaInMinutes + ' minutes ago';
    }
    if (deltaInSeconds > 45 && deltaInSeconds <= 90) {
        return 'a minute ago';
    }

    return 'a few seconds ago';

  }

  getSeconds(valuems: number) {
    return valuems / 1000;
  }

  getMinutes(valuesms: number) {
      return this.getSeconds(valuesms) / 60;
  }

  getHours(valuesms: number) {
      return this.getMinutes(valuesms) / 60;
  }

  getDays(valuesms: number) {
      return this.getHours(valuesms) / 24;
  }
}
